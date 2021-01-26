//nolint:errcheck
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/criticalstack/swoll/api/v1alpha1"
	"github.com/criticalstack/swoll/pkg/event"
	"github.com/criticalstack/swoll/pkg/kernel/metrics"
	"github.com/criticalstack/swoll/pkg/syscalls"
	"github.com/criticalstack/swoll/pkg/topology"
	"github.com/criticalstack/swoll/pkg/types"
	"github.com/go-echarts/go-echarts/charts"
	uuid "github.com/google/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type errResponse struct {
	Error string `json:"error,omitempty"`
}

type traceJob struct {
	ID    string          `json:"id"`
	Trace *v1alpha1.Trace `json:"traceSpec"`
	job   *topology.Job
}

type liveJobs struct {
	jobs map[string]*traceJob
	sync.RWMutex
}

const (
	// Time allowed to write to the client.
	writeWait = 10 * time.Second
	// Time allowed to read the next pong message from the client.
	pongWait = 30 * time.Second
	// Send pings to client with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10
	// default namespace is all
	defaultNamespace = ""
)

var (
	running = &liveJobs{
		jobs: make(map[string]*traceJob),
	}

	completed = &liveJobs{
		jobs: make(map[string]*traceJob),
	}

	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
)

var cmdServer = &cobra.Command{
	Use:   "server",
	Short: "Start the swoll-server",
	Run:   runServer,
}

func init() {
	rootCmd.AddCommand(cmdServer)

	cmdServer.Flags().Bool("use-tls", false, "Use TLS")
	cmdServer.Flags().String("cert", "", "TLS certificate file")
	cmdServer.Flags().String("key", "", "TLS key")
	cmdServer.Flags().Bool("no-metrics", false, "Disable metric collection")
	cmdServer.Flags().StringP("listen-addr", "l", ":9095", "Listen address")
}

func (t *traceJob) MarshalJSON() ([]byte, error) {
	type Alias traceJob
	return json.Marshal(&struct {
		Containers []string `json:"monitoredHosts"`
		*Alias
	}{
		Containers: t.job.MonitoredHosts(true),
		Alias:      (*Alias)(t),
	})
}

func (r *liveJobs) add(job *traceJob) error {
	if found, _ := r.get(job.ID); found != nil {
		return fmt.Errorf("trace job %s already running", job.ID)
	}

	r.Lock()
	r.jobs[job.ID] = job
	r.Unlock()
	return nil

}

func (r *liveJobs) get(id string) (*traceJob, error) {
	r.RLock()
	defer r.RUnlock()

	if _, ok := r.jobs[id]; ok {
		return r.jobs[id], nil
	}

	return nil, fmt.Errorf("job not found")
}

func (r *liveJobs) remove(id string) error {
	if _, err := r.get(id); err != nil {
		return err
	}

	r.Lock()
	delete(r.jobs, id)
	r.Unlock()
	return nil
}

func errorHandler(w http.ResponseWriter, code int, errstr string) {
	w.WriteHeader(code)

	j, err := json.Marshal(errResponse{errstr})
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(j); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
}

func successHandler(w http.ResponseWriter, code int, buf interface{}) {
	w.WriteHeader(code)

	if buf != nil {
		d, err := json.MarshalIndent(buf, "", " ")
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(d)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
	}
}

func jobReader(c *websocket.Conn) {
	defer c.Close()

	c.SetReadLimit(1024)
	if err := c.SetReadDeadline(time.Now().Add(pongWait)); err != nil {
		log.Warnf("Error setting read deadline: %v", err)
		return
	}

	c.SetPongHandler(
		func(string) error {
			return c.SetReadDeadline(time.Now().Add(pongWait))
		},
	)
	c.SetPingHandler(func(message string) error {
		err := c.WriteControl(websocket.PongMessage, []byte(message), time.Time{})
		return err
	})

	for {
		if _, _, err := c.ReadMessage(); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway) {
				log.Warnf("Error: %v", err)
			}
			break
		}
	}

}

// jobWriter attaches the current websocket to the running job and deals with
// the PING messages from the server. It also routes the ouput of a job back to
// the websocket client
func jobWriter(job *traceJob, h *topology.Hub, c *websocket.Conn) {
	tickr := time.NewTicker(pingPeriod)

	unsub := h.AttachTrace(job.Trace,
		func(name string, ev *event.TraceEvent) {
			if err := c.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
				return
			}
			if err := c.WriteJSON(ev); err != nil {
				return
			}
		})

	defer func() {
		tickr.Stop()
		c.Close()
		unsub()
	}()

	for {
		<-tickr.C
		if err := c.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
			log.Warnf("Error setting write deadline: %v", err)
			return
		}

		if err := c.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
			log.Warnf("Error writing ping message: %v", err)
			return
		}
	}
}

// traceWriter acts like jobWriter, but for specific traces (as in not a job,
// but a subset of a job). See `traceWatchHandler`
func traceWriter(paths []string, h *topology.Hub, c *websocket.Conn) {
	tickr := time.NewTicker(pingPeriod)
	defer func() {
		tickr.Stop()
		c.Close()
	}()

	h.AttachPath("running", paths,
		func(name string, ev *event.TraceEvent) {
			if err := c.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
				log.Warnf("SetWriteDeadline failed: %v", err)
				return
			}

			if err := c.WriteJSON(ev); err != nil {
				return
			}
		})

	for {
		<-tickr.C
		if err := c.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
			log.Warnf("SetWriteDeadline failed with error %v", err)
			return
		}

		if err := c.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
			log.Warnf("Error writing ping message: %v", err)
			return
		}
	}
}

// traceWatchHandler processes subset queries and outputs it to the websocket
func traceWatchHandler(ctx context.Context, hub *topology.Hub) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		args := mux.Vars(r)
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			errorHandler(w, http.StatusInternalServerError, err.Error())
			return
		}

		go traceWriter([]string{
			args["ns"],
			args["pod"],
			args["container"]}, hub, conn)
		jobReader(conn)
	}
}

// getJobsHandler gets information about a collection of jobs from this endpoint
func getJobsHandler(ctx context.Context, hub *topology.Hub) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		running.RLock()
		completed.RLock()

		successHandler(w, http.StatusOK, map[string]interface{}{
			"running":   running.jobs,
			"completed": completed.jobs})

		completed.RUnlock()
		running.RUnlock()
	}
}

// getJobHandler returns job information about a given job. If `id` is
// specified, it will use the value as the jobID, otherwise the query arguments
// are used.
func getJobHandler(ctx context.Context, hub *topology.Hub) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		jobid := mux.Vars(r)["id"]
		job, err := running.get(jobid)
		if err != nil {
			errorHandler(w, http.StatusNotFound, err.Error())
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			errorHandler(w, http.StatusInternalServerError, err.Error())
			return
		}

		go jobWriter(job, hub, conn)
		jobReader(conn)
	}
}

// createJobHandler constructs a v1alpha1.Trace type and creates the resource
func createJobHandler(ctx context.Context, hb *topology.Hub) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var jobid string

		args := mux.Vars(r)
		ns := args["ns"]

		query := r.URL.Query()

		if jid, ok := query["id"]; ok {
			// if the query arguments included an id, use that string as the
			// jobID which we will post.
			jobid = jid[0]
		} else {
			// otherweise, just give us a random-id to return
			jobid = uuid.New().String()
		}

		if ns == "" {
			errorHandler(w, http.StatusNotFound, "namespace not found")
			return
		}

		var spec v1alpha1.TraceSpec

		// read in the trace spec from the client
		if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
			errorHandler(w, http.StatusBadRequest, err.Error())
			return
		}

		// generate an entire Trace context using info from the spec
		trace := &v1alpha1.Trace{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns,
				SelfLink:  "/jobs/" + jobid,
			},
			Spec: spec,
			Status: v1alpha1.TraceStatus{
				JobID: jobid,
			},
		}

		job := traceJob{jobid, trace, topology.NewJob(trace)}

		// add this job to the running list of jobs
		if err := running.add(&job); err != nil {
			errorHandler(w, http.StatusInternalServerError, err.Error())
			return
		}

		// execute the trace in its own goroutine
		go hb.MustRunJob(ctx, job.job)

		successHandler(w, http.StatusCreated, job)
	}
}

func deleteJob(job *traceJob, hub *topology.Hub) error {
	// Delete the job from our probe-hub
	if err := hub.DeleteTrace(job.Trace); err != nil {
		return err
	}

	// remove this job from our running list
	if err := running.remove(job.ID); err != nil {
		return err
	}

	// add this job to our completed list
	if err := completed.add(job); err != nil {
		return err
	}

	return nil

}

// deleteJobHandler is exeucted when a user attempts to delete a resource.
func deleteJobHandler(ctx context.Context, hub *topology.Hub) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		jobid := mux.Vars(r)["id"]
		job, err := running.get(jobid)
		if err != nil {
			errorHandler(w, http.StatusNotFound, err.Error())
			return
		}

		if err := deleteJob(job, hub); err != nil {
			errorHandler(w, http.StatusInternalServerError, err.Error())
			return
		}

		successHandler(w, http.StatusOK, "OK")
	}
}

// Metrics is a controlling structure for generating the charts from metrics
type Metrics struct {
	handle *metrics.Handler
	topo   *topology.Topology
}

type metricOrderKey int

const (
	ordScGroup metricOrderKey = iota
	ordScClass
	ordScName
	ordErrno
	ordNamespace
	ordPod
	ordContainer
)

// parseOrder parses a comma-delimited set of strings into the corresponding
// `ord` array.
func (m *Metrics) parseOrder(order string) []metricOrderKey {
	ret := make([]metricOrderKey, 0)

	for _, tok := range strings.Split(order, ",") {
		switch tok {
		case "class", "cl":
			ret = append(ret, ordScClass)
		case "gr", "group":
			ret = append(ret, ordScGroup)
		case "ns", "namespace":
			ret = append(ret, ordNamespace)
		case "p", "pod":
			ret = append(ret, ordPod)
		case "n", "name", "syscall", "sc":
			ret = append(ret, ordScName)
		case "e", "error", "errno":
			ret = append(ret, ordErrno)
		case "c", "container":
			ret = append(ret, ordContainer)
		}
	}

	return ret
}

type wordClouds struct {
	mu sync.Mutex
	*Metrics
	Errno     map[string]interface{} `json:"errno,omitempty"`
	Class     map[string]interface{} `json:"class,omitempty"`
	Namespace map[string]interface{} `json:"namespace,omitempty"`
}

func newWordClouds(mhandle *Metrics) *wordClouds {
	return &wordClouds{
		Metrics:   mhandle,
		Errno:     make(map[string]interface{}),
		Class:     make(map[string]interface{}),
		Namespace: make(map[string]interface{}),
	}
}

func (w *wordClouds) updateClass(in *metrics.Metric) {
	if in == nil {
		return
	}

	count := in.Count()
	syscall := syscalls.Lookup(in.Syscall())
	if syscall == nil {
		return
	}

	if val, ok := w.Class[syscall.Class]; ok {
		w.Class[syscall.Class] = count + val.(uint64)
	} else {
		w.Class[syscall.Class] = count
	}
}

func (w *wordClouds) updateNamespace(in *metrics.Metric) {
	if in == nil {
		return
	}

	count := in.Count()
	ctr, err := w.topo.LookupContainer(context.TODO(), in.PidNamespace())
	if err != nil {
		return
	}

	if val, ok := w.Namespace[ctr.Namespace]; ok {
		w.Namespace[ctr.Namespace] = count + val.(uint64)
	} else {
		w.Namespace[ctr.Namespace] = count
	}
}

func (w *wordClouds) updateErrno(in *metrics.Metric) {
	if in == nil {
		return
	}
	count := in.Count()
	errno := types.Errno(in.Errno())

	if errno == types.OK {
		// ignore non-error counts
		return
	}

	errstr := errno.String()

	if val, ok := w.Errno[errstr]; ok {
		w.Errno[errstr] = count + val.(uint64)
	} else {
		w.Errno[errstr] = count
	}
}

func (w *wordClouds) updateMetric(in *metrics.Metric) {
	w.updateErrno(in)
	w.updateNamespace(in)
	w.updateClass(in)
}

func (w *wordClouds) updateMetrics(in metrics.Metrics) {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, m := range in {
		w.updateMetric(&m)
	}
}

func (m *Metrics) errnoWordCloud(wc *wordClouds) *charts.WordCloud {
	return charts.NewWordCloud().
		SetGlobalOptions(charts.TitleOpts{Title: "errno"}).
		Add("errno", wc.Errno,
			charts.WordCloudOpts{SizeRange: []float32{8, 75}})
}

func (m *Metrics) classWordCloud(wc *wordClouds) *charts.WordCloud {
	return charts.NewWordCloud().
		SetGlobalOptions(charts.TitleOpts{Title: "errno"}).
		Add("errno", wc.Class,
			charts.WordCloudOpts{SizeRange: []float32{8, 75}})
}

func (m *Metrics) namespaceWordCloud(wc *wordClouds) *charts.WordCloud {
	return charts.NewWordCloud().
		SetGlobalOptions(charts.TitleOpts{Title: "errno"}).
		Add("errno", wc.Namespace,
			charts.WordCloudOpts{SizeRange: []float32{8, 75}})
}

func (m *Metrics) sankey(ns, ordString string) *charts.Sankey {
	nodes := []charts.SankeyNode{}
	links := []charts.SankeyLink{}
	sanky := charts.NewSankey().SetGlobalOptions(
		charts.TitleOpts{Title: "sankey-flows"},
		charts.InitOpts{
			PageTitle: "sankey-flows",
			Height:    "1500px",
			Width:     "1500px",
			Theme:     charts.ThemeType.Vintage,
		})

	// default sankey flow order: class->group->ns->pod->syscall->errno
	// XXX[lz]: make this a query argument.
	var order []metricOrderKey

	if ordString == "" {
		if ns == "" {
			// by default, if no namespace is defined in the arguments, we do:
			// class -> group -> namespace -> pod -> syscall -> error
			order = []metricOrderKey{
				ordScClass,
				ordScGroup,
				ordNamespace,
				ordPod,
				ordScName,
				ordErrno,
			}
		} else {
			// if the namespace is provided in the arguments, just exclude the
			// namespace entry from the connected nodes.
			order = []metricOrderKey{
				ordScClass,
				ordScGroup,
				ordPod,
				ordContainer,
				ordScName,
				ordErrno,
			}
		}
	} else {
		// if the ordering is found in the arguments, apply the user-defined
		// ordering to our output.
		order = m.parseOrder(ordString)
	}

	// find a link matching src -> dst
	findLink := func(src, dst string) int {
		for i, link := range links {
			if link.Source == src && link.Target == dst {
				return i
			}
		}
		return -1
	}

	// find a node-entry matching `name`
	findNode := func(name string) int {
		for i, node := range nodes {
			if node.Name == name {
				return i
			}
		}
		return -1
	}

	// add or update a link between two nodes.
	addLink := func(src, dst string, count float32) {
		if i := findLink(src, dst); i != -1 {
			// link already made, add this count to the sum
			links[i].Value += count
		} else {
			links = append(links, charts.SankeyLink{
				Source: src,
				Target: dst,
				Value:  count})
		}

		if i := findNode(src); i == -1 {
			nodes = append(nodes, charts.SankeyNode{Name: src})
		}

		if i := findNode(dst); i == -1 {
			nodes = append(nodes, charts.SankeyNode{Name: dst})
		}
	}

	// return the value of the field associated with the metricsOrderKey
	// e.g., ordScGroup=syscall.Group
	//       ordScName=syscall.Name etc...
	// a basic way to allow for dynamic ordering to our sankey diagram.
	ordVal := func(ktype metricOrderKey, sc *syscalls.Syscall, c *types.Container, e types.Errno) string {
		switch ktype {
		case ordScGroup:
			return sc.Group
		case ordScClass:
			return sc.Class
		case ordScName:
			return sc.Name
		case ordErrno:
			return e.String()
		case ordNamespace:
			return c.Namespace
		case ordPod:
			return c.Pod
		case ordContainer:
			return c.Name
		}
		return ""
	}

	for _, metricdata := range m.handle.QueryAll() {
		// attempt to "resolve" the raw kernel namespace to kube container in
		// which it originated.
		ctr, err := m.topo.LookupContainer(context.TODO(), metricdata.PidNamespace())
		if err != nil {
			// ignore kernel-namespace -> container resolution errors
			continue
		}

		if ns != "" && ctr.Namespace != ns {
			continue
		}

		count := float32(metricdata.Count())
		syscall := syscalls.Lookup(int(metricdata.Syscall()))
		errn := types.Errno(metricdata.Errno())

		for idx, ord := range order {
			if idx+1 <= len(order)-1 {
				addLink(
					ordVal(ord, syscall, ctr, errn),
					ordVal(order[idx+1], syscall, ctr, errn), count)
			}
		}
	}

	sanky.Add("syscalls", nodes, links,
		charts.LabelTextOpts{Show: true},
		charts.LineStyleOpts{Curveness: 0.5, Color: "source"},
	)

	return sanky

}

func runServer(cmd *cobra.Command, args []string) {
	log.Infoln("Checking install...")
	if err := runSelfTest(true); err != nil {
		log.Fatal(err)
	}

	noMetrics, err := cmd.Flags().GetBool("no-metrics")
	if err != nil {
		log.Fatal(err)
	}

	crisock, err := cmd.Flags().GetString("cri")
	if err != nil {
		log.Fatal(err)
	}

	if crisock == "" {
		crisock = os.Getenv("SWOLL_CRISOCKET")
	}

	kconfig, err := cmd.Flags().GetString("kubeconfig")
	if err != nil {
		log.Fatal(err)
	}

	if kconfig == "" {
		kconfig = os.Getenv("SWOLL_KUBECONFIG")
	}

	altroot, err := cmd.Flags().GetString("altroot")
	if err != nil {
		log.Fatal(err)
	}

	if altroot == "" {
		altroot = os.Getenv("SWOLL_ALTROOT")
	}

	laddr, err := cmd.Flags().GetString("listen-addr")
	if err != nil {
		log.Fatal(err)
	}

	router := mux.NewRouter().StrictSlash(true)
	handler := handlers.LoggingHandler(os.Stdout, router)
	server := &http.Server{
		Addr:    laddr,
		Handler: handler,
	}

	bpf, err := loadBPFargs(cmd, args)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	// process with k8s support using a Kubernetes Observer for the
	// Topology API:
	topo, err := topology.NewKubernetes(
		topology.WithKubernetesCRI(crisock),
		topology.WithKubernetesConfig(kconfig),
		// we use an empty label match here since we pretty dumb and only
		// use this as our resolver context for incoming messages
		topology.WithKubernetesLabelSelector("swoll!=false"),
		topology.WithKubernetesProcRoot(altroot))
	if err != nil {
		log.Fatal(err)
	}

	hb, err := topology.NewHub(bytes.NewReader(bpf), topo)
	/*
		&hub.Config{
			AltRoot:     altroot,
			BPFObject:   bpf,
			CRIEndpoint: crisock,
			K8SEndpoint: kconfig}, topo)
	*/
	if err != nil {
		log.Fatal(err)
	}

	if err := SetOffsetsFromArgs(hb.Probe(), cmd, args); err != nil {
		log.Fatal(err)
	}

	// job handling callbacks
	router.HandleFunc("/jobs", getJobsHandler(ctx, hb)).Methods("GET")
	router.HandleFunc("/jobs/{id}", websockRedir).Methods("GET")
	router.HandleFunc("/jobs/{id}", deleteJobHandler(ctx, hb)).Methods("DELETE")
	router.HandleFunc("/jobs/{id}/ws", getJobHandler(ctx, hb)).Methods("GET")
	router.HandleFunc("/jobs/{id}/status", getJobHandler(ctx, hb)).Methods("GET")
	router.HandleFunc("/jobs/namespaces/{ns}", createJobHandler(ctx, hb)).Methods("POST")

	// trace-job handling callbacks
	router.HandleFunc("/trace", websockRedir).Methods("GET")
	router.HandleFunc("/trace/ws", traceWatchHandler(ctx, hb)).Methods("GET")
	router.HandleFunc("/trace/namespaces/{ns}", websockRedir).Methods("GET")
	router.HandleFunc("/trace/namespaces/{ns}/ws", traceWatchHandler(ctx, hb)).Methods("GET")
	router.HandleFunc("/trace/namespaces/{ns}/pods/{pod}", websockRedir).Methods("GET")
	router.HandleFunc("/trace/namespaces/{ns}/pods/{pod}/ws", traceWatchHandler(ctx, hb)).Methods("GET")
	router.HandleFunc("/trace/namespaces/{ns}/pods/{pod}/containers/{container}", websockRedir).Methods("GET")
	router.HandleFunc("/trace/namespaces/{ns}/pods/{pod}/containers/{container}/ws", traceWatchHandler(ctx, hb)).Methods("GET")

	// initialize our metrics handler if enabled.
	if !noMetrics {
		// Create a new metrics handler based off of our probe's module
		metricsHdl := metrics.NewHandler(hb.Probe().Module())
		mhandler := &Metrics{metricsHdl, hb.Topology()}
		wordcloud := newWordClouds(mhandler)

		prometheus.MustRegister(newPrometheusWorker(metricsHdl, hb.Topology()))
		router.Handle("/metrics", promhttp.Handler())

		chartsRouter := router.PathPrefix("/metrics/charts").Subrouter()
		routerOpts := []charts.RouterOpts{
			{
				URL:  "/metrics/charts/sankey",
				Text: "sk",
			},
			{
				URL:  "/metrics/charts/wc/errno",
				Text: "Errno WordCloud",
			},
			{
				URL:  "/metrics/charts/wc/class",
				Text: "Class WordCloud",
			},
			{
				URL:  "/metrics/charts/wc/ns",
				Text: "Namespace WordCloud",
			},
		}

		chartsRouter.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			query := r.URL.Query()
			ns := query.Get("namespace")
			ord := query.Get("ord")

			wordcloud.updateMetrics(metricsHdl.QueryAll())
			charts.NewPage(routerOpts...).Add(
				mhandler.sankey(ns, ord),
				mhandler.errnoWordCloud(wordcloud),
				mhandler.classWordCloud(wordcloud),
				//nolint:errcheck
				mhandler.namespaceWordCloud(wordcloud)).Render(w)
		}).Methods("GET")

		chartsRouter.HandleFunc("/sankey", func(w http.ResponseWriter, r *http.Request) {
			//nolint:errcheck
			mhandler.sankey(defaultNamespace, "").Render(w)
		}).Methods("GET")

		chartsRouter.HandleFunc("/wc/errno", func(w http.ResponseWriter, r *http.Request) {
			//nolint:errcheck
			mhandler.errnoWordCloud(wordcloud).Render(w)
		}).Methods("GET")

		chartsRouter.HandleFunc("/wc/class", func(w http.ResponseWriter, r *http.Request) {
			//nolint:errcheck
			mhandler.classWordCloud(wordcloud).Render(w)
		}).Methods("GET")

		chartsRouter.HandleFunc("/wc/ns", func(w http.ResponseWriter, r *http.Request) {
			//nolint:errcheck
			mhandler.namespaceWordCloud(wordcloud).Render(w)
		}).Methods("GET")

	}

	if tlsOn, _ := cmd.Flags().GetBool("use-tls"); tlsOn {
		key, _ := cmd.Flags().GetString("key")
		crt, _ := cmd.Flags().GetString("cert")

		//nolint:errcheck
		go server.ListenAndServeTLS(crt, key)
	} else {
		//nolint:errcheck
		go server.ListenAndServe()
	}

	go hb.MustRun(ctx)
	shutdown(server)
}

// websockRedir is a function which redirects the current URI to the websock URI
func websockRedir(w http.ResponseWriter, r *http.Request) {
	baseHTML := `<html><head><title>stupid</title><body>
            <pre id="data"></pre>
            <script>
                var sock = new WebSocket(((window.location.protocol === "https:") ? "wss://" : "ws://") + window.location.host + window.location.pathname + "/ws");

                sock.onmessage = function(msg) {
                    var data = document.getElementById("data");
                    data.append(msg.data+"\n")
                }
            </script></body></html>`

	w.Header().Set("Content-Type", "text/html")
	if _, err := w.Write([]byte(baseHTML)); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
}

// shutdown will terminate the process in a nice manner.
func shutdown(server *http.Server) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c

	log.Infoln("Shutting down....")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Warnf("failed to shutdown server %v\n", err)
		return
	}

	log.Infoln("shutting down server\n")
}
