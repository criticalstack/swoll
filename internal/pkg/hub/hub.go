package hub

import (
	"bytes"
	"container/list"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/criticalstack/swoll/api/v1alpha1"
	"github.com/criticalstack/swoll/internal/pkg/pubsub"
	"github.com/criticalstack/swoll/pkg/event"
	"github.com/criticalstack/swoll/pkg/event/reader"
	"github.com/criticalstack/swoll/pkg/kernel"
	"github.com/criticalstack/swoll/pkg/kernel/filter"
	"github.com/criticalstack/swoll/pkg/kernel/metrics"
	"github.com/criticalstack/swoll/pkg/syscalls"
	"github.com/criticalstack/swoll/pkg/topology"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Hub maintains the global kernel probe and all the underlying
// filters and event message routing.
type Hub struct {
	config *Config
	// map pid-namespace+syscall_nr to a list of JobContext's
	nsmap map[int]map[int]*JobList
	// map job-ids to lists of JobContext's
	idmap map[string]*JobList
	// the pubsub socket to write our events to
	ps *pubsub.PubSub
	// the underlying kernel probe context
	probe *kernel.Probe
	// the kernel probe filtering api context
	filter *filter.Filter
	// the topology context for this hub which is used for resolving kernel
	// namespaces to pods/containers
	topo          *topology.Topology
	statsInterval time.Duration
	sync.Mutex
}

// RunJob runs a job on the Hub
func (h *Hub) RunJob(ctx context.Context, job *Job) error {
	return job.Run(ctx, h)
}

// MustRunJob calls hub.RunJob but exits on any errors
func (h *Hub) MustRunJob(ctx context.Context, job *Job) {
	if err := h.RunJob(ctx, job); err != nil {
		log.Fatal(err)
	}
}

// RunTrace runs a TraceJob on the hub
func (h *Hub) RunTrace(ctx context.Context, t *v1alpha1.Trace) error {
	return h.RunJob(ctx, NewJob(t))
}

// DeleteTrace will stop all the running jobs that are associated with this
// Trace specification. using the job-id, we iterate over each context and
// if there are no other jobs trying to use the syscall and pod associated
// with this, the kernel filters are removed.
func (h *Hub) DeleteTrace(t *v1alpha1.Trace) error {
	h.Lock()
	defer h.Unlock()

	jidlist := h.findJobListByID(t.Status.JobID)
	if jidlist == nil {
		return errors.New("job not found")
	}

	var next *list.Element

	for j := jidlist.Front(); j != nil; j = next {
		next = j.Next()
		ctx := j.Value.(*JobContext)

		// find our bucket in our `nsmap` hash using this
		// contexts kernel-namespace and syscall-nr.
		jnslist := h.findJobList(ctx.ns, ctx.nr)
		if jnslist == nil {
			log.Warnf("job-namespace-list is nil for %v %v", ctx.ns, ctx.nr)
			continue
		}

		// delete this element from the namespace map
		log.Tracef("Removing %s/%s from namespace-list\n", ctx.JobID(), syscalls.Lookup(ctx.nr))
		jnslist.Remove(ctx.nselem)

		// if our `nsmap` is now empty, we can safely remove
		// this from the running kernel filter.
		if jnslist.Len() == 0 {
			log.Tracef("Bucket for %s/%s empty, dumping job bucket.\n", ctx.JobID(), syscalls.Lookup(ctx.nr))

			if err := h.filter.RemoveSyscall(ctx.nr, ctx.ns); err != nil {
				log.Warnf("Failed to remove syscall from kernel-filter: %v", err)
			}

			h.clearJobList(ctx.ns, ctx.nr)
		}

		// now delete this element from the id map
		jidlist.Remove(ctx.idelem)

		// if our `nsmap` bucket for just the pidnamespace (key) is empty,
		// we can safely remove the pod from our nsmap
		if len(h.nsmap[ctx.ns]) == 0 {
			log.Tracef("Removing %d from the nsmap\n", ctx.ns)
			delete(h.nsmap, ctx.ns)

		}

		// mark the context as completed and set the correct timestamp
		now := metav1.NewTime(time.Now())
		ctx.Status.CompletionTime = &now

	}

	if jidlist.Len() != 0 {
		log.Fatalf("jidlist.Len != 0 (%d)", jidlist.Len())
	}

	// Clear out the bucket for our job-id
	delete(h.idmap, t.Status.JobID)

	return nil
}

// WriteEvent writes a single TraceEvent to all subscribers
func (h *Hub) WriteEvent(ev *event.TraceEvent) {
	h.ps.Publish(ev, pubsub.LinearTreeTraverser(
		hashPath(swNsStream, ev.Container.Namespace,
			ev.Container.Pod, ev.Container.Name, ev.Syscall.Name)))
}

// Run starts up and runs the global kernel probe and maintains various
// state. For each event that is recv'd via the bpf, we decode it (`Ingest`),
// find all jobs associated with this message, and publish the event to
// the streams tied to the jobs.
func (h *Hub) Run(ctx context.Context) error {
	// initialize our kernel reader used to read messages from the kernel.
	proberdr := reader.NewEventReader(h.probe)
	//nolint:errcheck
	go proberdr.Run(ctx)

	// initialize our topology reader which is used for resolving
	// kernel-namespaces back to the container/pod it was sourced from.
	topordr := reader.NewEventReader(h.topo)
	// nolint:errcheck
	go topordr.Run(ctx)

	mhandler := metrics.NewHandler(h.probe.Module())
	sinterval := h.statsInterval
	if sinterval == 0 {
		sinterval = 5 * time.Second
	}

	stattick := time.NewTicker(sinterval)

	msg := new(event.TraceEvent).WithTopology(h.topo)

	for {
		select {
		case <-stattick.C:
			log.Infof("allocated-metric-nodes: %v", len(mhandler.QueryAll()))

		case ev := <-topordr.Read():
			// we keep an active podmon reader available for kernel-namespace to
			// container resolution
			switch ev := ev.(type) {
			case event.ContainerAddEvent:
				log.Tracef("adding container to metrics watcher: %s", ev.Container.FQDN())

				h.filter.AddMetrics(ev.PidNamespace)
			case event.ContainerDelEvent:
				log.Tracef("removing/pruning container from metrics watcher: %s", ev.Container.FQDN())

				h.filter.RemoveMetrics(ev.PidNamespace)
				mhandler.PruneNamespace(ev.PidNamespace)

			}

		case ev := <-proberdr.Read():
			// read a single event from the kernel, allcoate empty TraceEvent,
			// initialize the underlying with the topology resolver
			if _, err := msg.Ingest(ev); err != nil {
				continue
			}

			// We were unable to obtain any container information about this
			// message, this could be for several reasons, but we just ignore
			// for now.
			if msg.Container == nil {
				continue
			}

			h.Lock()

			// fetch the jobs associated with this namespace and syscall nr.
			jlist := h.findJobList(msg.PidNamespace, msg.Syscall.Nr)
			if jlist != nil {
				// write to the global pubsub channel
				h.WriteEvent(msg)

				// iterate over each sub-job and write to its output channel.
				for j := jlist.Front(); j != nil; j = j.Next() {
					// write to our job-specific channel
					j.Value.(*JobContext).WriteEvent(h, msg)
				}
			} else {
				log.Tracef("no jobs matched for %v/%v", msg.PidNamespace, msg.Syscall)
			}

			h.Unlock()
		}
	}

}

func (h *Hub) MustRun(ctx context.Context) {
	if err := h.Run(ctx); err != nil {
		log.Fatal(err)
	}
}

// findJobList will search through the running rules using the pid-namespace,
// and syscall-nr as a key. The value will be all jobs pushed via `PushJob` for
// this specific ns+nr.
func (h *Hub) findJobList(ns, nr int) *JobList {
	if tbl, ok := h.nsmap[ns]; ok {
		return tbl[nr]
	}

	return nil
}

func (h *Hub) clearJobList(ns, nr int) {
	if tbl, ok := h.nsmap[ns]; ok {
		delete(tbl, nr)
	}
}

func (h *Hub) findJobListByID(id string) *JobList {
	return h.idmap[id]
}

// PushJob insert a namespace+nr specific job as a value of a list in two
// buckets; the first being the `nsmap`, a mapping of pidNamespace + syscall_NR
// to lists of jobs, and an `idmap`, a mapping of jobID's to jobs.
//
// We keep these lists like this so that if two jobs that have overlapping rules
// (e.g., rule-A=syscall_A,syscall_B, rule-B=syscall_A,syscall_C) we don't
// accidentally delete a running check for `syscall_A` if `rule-B` is removed.
func (h *Hub) PushJob(job *Job, ns, nr int) {
	h.Lock()
	defer h.Unlock()

	jobctx := &JobContext{Job: job, ns: ns, nr: nr}
	jobid := job.JobID()
	joblist := h.findJobList(ns, nr)

	if joblist == nil {
		// No running rules that match this job, so initialize
		// the underlying structures and push this context into the list
		if _, ok := h.nsmap[ns]; !ok {
			h.nsmap[ns] = make(map[int]*JobList)
		}

		joblist = &JobList{list.New()}
		h.nsmap[ns][nr] = joblist
	}
	jobctx.nselem = joblist.PushBack(jobctx)

	// Create a reference insider our job-id lookup table
	if _, ok := h.idmap[jobid]; !ok {
		h.idmap[jobid] = &JobList{list.New()}
	}

	jobctx.idelem = h.idmap[jobid].PushBack(jobctx)

}

func (h *Hub) findLowestSampleJob(ns, nr int) *JobContext {
	joblist := h.findJobList(ns, nr)
	if joblist == nil {
		return nil
	}

	min := joblist.Front().Value.(*JobContext)

	for j := joblist.Front(); j != nil; j = j.Next() {
		ctx := j.Value.(*JobContext)

		if ctx.Spec.SampleRate < min.Spec.SampleRate {
			min = ctx
		}
	}

	return min
}

// NewHub creates and initializes a Hub context for reading and writing data to
// the kernel probe and routing them to the clients that care.
func NewHub(config *Config, observer topology.Observer) (*Hub, error) {
	if len(config.BPFObject) == 0 {
		return nil, errors.New("BPF object missing")
	}

	probe, err := kernel.NewProbe(bytes.NewReader(config.BPFObject), nil)
	if err != nil {
		return nil, err
	}

	if err := probe.InitProbe(); err != nil {
		return nil, err
	}

	filter, err := filter.NewFilter(probe.Module())
	if err != nil {
		return nil, err
	}

	if err := filter.FilterSelf(); err != nil {
		return nil, err
	}

	// we need to have at least one syscall in our filter (which will never
	// actually match anything) when we start with a clean slate.
	if err := filter.AddSyscall("sys_set_tid_address", 0); err != nil {
		return nil, err
	}

	// add a stub/dummy metrics filter so we don't dump everything.
	if err := filter.AddMetrics(31337); err != nil {
		return nil, err
	}

	return &Hub{
		config: config,
		nsmap:  make(map[int]map[int]*JobList),
		idmap:  make(map[string]*JobList),
		ps:     pubsub.New(),
		probe:  probe,
		filter: filter,
		topo:   topology.NewTopology(observer),
	}, nil
}

// Topology returns this Hub's current underlying topology context
func (h *Hub) Topology() *topology.Topology {
	if h != nil {
		return h.topo
	}

	return nil
}

// Probe returns the Hub's current kernel.Probe context
func (h *Hub) Probe() *kernel.Probe {
	if h != nil {
		return h.probe
	}

	return nil
}

// AttachTrace will subscribe the caller to a stream which has the output of a
// specific job.
func (h *Hub) AttachTrace(t *v1alpha1.Trace, cb func(n string, ev *event.TraceEvent)) pubsub.Unsubscriber {
	return h.ps.Subscribe(
		func(data interface{}) {
			cb(t.Status.JobID, data.(*event.TraceEvent))
		}, pubsub.WithPath(hashPath(swJobStream, t.Status.JobID)))
}

// AttachPath will subscribe the caller to a stream which is a subset of data
// sent to a specific job.
func (h *Hub) AttachPath(name string, paths []string, cb func(string, *event.TraceEvent)) pubsub.Unsubscriber {
	tpaths := []string{swNsStream}
	tpaths = append(tpaths, paths...)

	return h.ps.Subscribe(
		func(data interface{}) {
			cb(name, data.(*event.TraceEvent))
		}, pubsub.WithPath(hashPath(tpaths...)))
}
