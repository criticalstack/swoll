package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/criticalstack/swoll/pkg/kernel/assets"
	"github.com/criticalstack/swoll/pkg/kernel/metrics"
	"github.com/criticalstack/swoll/pkg/syscalls"
	"github.com/criticalstack/swoll/pkg/topology"
	"github.com/criticalstack/swoll/pkg/types"
	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	gometrics "github.com/rcrowley/go-metrics"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var mu sync.RWMutex

var (
	aggregateHosts = false
)

type Counter struct {
	count float64
}

func (c *Counter) Count() float64 {
	return c.count
}

func (c *Counter) Inc(i float64) {
	c.count += i
}

func newCounter() Counter {
	return Counter{0}
}

type metricKey struct {
	pod string
	ns  string
	ctr string
	sc  string
	err string
}

type metricVal struct {
	key   *metricKey
	count Counter
	rate  gometrics.Meter
}

type aggSPair struct {
	key metricKey
	val *metricVal
}

type aggMetrics map[metricKey]*metricVal

type aggWidget struct {
	*widgets.Table
}

type fixedRateArray struct {
	values []float64
	elems  int
}

func newFixedRateArray(n int) *fixedRateArray {
	return &fixedRateArray{
		values: make([]float64, n),
		elems:  n,
	}
}

func (a *fixedRateArray) push(value float64) {
	a.values = append(a.values, value)
	if len(a.values) > a.elems {
		a.values = a.values[1:]
	}
}

func (m aggMetrics) mergeStatsByKey(erronly bool, keys ...string) aggMetrics {
	mu.RLock()
	defer mu.RUnlock()

	ret := newAggMetrics()

	for k, v := range m {
		var nkey metricKey

		if erronly && k.err == "OK" {
			continue
		}

		for _, kkey := range keys {
			switch kkey {
			case "pod":
				nkey.pod = k.pod
			case "ns":
				nkey.ns = k.ns
			case "ctr":
				nkey.ctr = k.ctr
			case "sc":
				nkey.sc = k.sc
			case "err":
				nkey.err = k.err
			}
		}

		if _, ok := ret[nkey]; !ok {
			ret[nkey] = newAggMetricVal(nkey)
		}

		ret[nkey].count.Inc(v.count.Count())
		ret[nkey].rate.Mark(int64(v.count.Count()))
	}

	return ret

}

func (m *aggMetrics) makeSortable(which int) []aggSPair {
	var sortable []aggSPair

	mu.RLock()
	defer mu.RUnlock()

	for key, val := range *m {
		sortable = append(sortable, aggSPair{key, val})
	}

	sort.Slice(sortable, func(i, j int) bool {
		switch which {
		case rtIdx:
			return sortable[i].val.rate.Rate1() > sortable[j].val.rate.Rate1()
		case cnIdx:
			return sortable[i].val.count.Count() > sortable[j].val.count.Count()
		case ctIdx:
			return sortable[i].key.ctr < sortable[j].key.ctr
		case pdIdx:
			return sortable[i].key.pod < sortable[j].key.pod
		case nsIdx:
			return sortable[i].key.ns < sortable[j].key.ns
		case esIdx:
			return sortable[i].key.err < sortable[j].key.err
		default:
			return sortable[i].val.rate.Rate1() > sortable[j].val.rate.Rate1()
		}
	})

	return sortable
}

func newAggregateWidget(metrics *aggMetrics) *aggWidget {
	ret := &aggWidget{
		Table: widgets.NewTable(),
	}

	ret.update(metrics)

	go func() {
		tick := time.NewTicker(time.Second)
		for {
			<-tick.C
			ret.update(metrics)
		}
	}()

	return ret
}

const (
	scIdx int = iota
	esIdx
	nsIdx
	pdIdx
	ctIdx
	cnIdx
	rtIdx
	mxIdx // always last
)

const maxIndex int = mxIdx

func max(x, y int) int {
	if x < y {
		return y
	}
	return x
}

func (w *aggWidget) update(metrics *aggMetrics) {
	if metrics == nil {
		return
	}

	mu.RLock()
	defer mu.RUnlock()

	sorted := metrics.makeSortable(rtIdx)
	lines := make([][]string, len(sorted)+1)
	if !aggregateHosts {
		lines[0] = make([]string, maxIndex)
	} else {
		lines[0] = make([]string, maxIndex-2)
	}
	lines[0][scIdx] = "Syscall"
	lines[0][esIdx] = "Errno"
	if !aggregateHosts {
		lines[0][nsIdx] = "Namespace"
		lines[0][pdIdx] = "POD"
		lines[0][ctIdx] = "Container"
		lines[0][cnIdx] = "Count"
		lines[0][rtIdx] = "Rate"
	} else {
		lines[0][nsIdx] = "Host"
		lines[0][pdIdx] = "Count"
		lines[0][ctIdx] = "Rate"
	}

	if len(sorted) > 0 {
		n := 0

		w.RowStyles = make(map[int]ui.Style)
		for _, unit := range sorted {
			n++
			if !aggregateHosts {
				lines[n] = make([]string, maxIndex)
			} else {
				lines[n] = make([]string, maxIndex-2)
			}
			lines[n][scIdx] = unit.key.sc
			lines[n][esIdx] = unit.key.err
			if !aggregateHosts {
				lines[n][nsIdx] = unit.key.ns
				lines[n][pdIdx] = unit.key.pod
				lines[n][ctIdx] = unit.key.ctr
				lines[n][cnIdx] = fmt.Sprintf("%v", unit.val.count.Count())
				lines[n][rtIdx] = fmt.Sprintf("%0.3f", unit.val.rate.RateMean())
			} else {
				lines[n][nsIdx] = fmt.Sprintf("%s.%s.%s", unit.key.ctr, unit.key.pod, unit.key.ns)
				lines[n][pdIdx] = fmt.Sprintf("%v", unit.val.count.Count())
				lines[n][ctIdx] = fmt.Sprintf("%0.3f", unit.val.rate.RateMean())
			}

			if unit.key.err != "OK" {
				w.RowStyles[n] = ui.NewStyle(ui.ColorYellow)
			}
		}
	}

	w.Rows = lines
	w.FillRow = true
	w.TextStyle = ui.NewStyle(ui.ColorWhite)
	w.RowSeparator = false
}

func mkaggMetricKey(container *types.Container, sc *syscalls.Syscall, errno types.Errno) metricKey {
	return metricKey{
		pod: container.Pod,
		ns:  container.Namespace,
		ctr: container.Name,
		sc:  sc.String(),
		err: errno.String(),
	}

}

func newAggMetrics() aggMetrics {
	return make(aggMetrics)
}

func newAggMetricVal(key metricKey) *metricVal {
	return &metricVal{
		key:   &key,
		count: newCounter(),
		rate:  gometrics.NewMeter(),
	}
}

func (a *metricVal) String() string {
	return fmt.Sprintf("key=%v, count=%v, rate=%v", a.key, a.count.Count(), a.rate.RateMean())
}

func (m aggMetrics) lookup(container *types.Container, sc *syscalls.Syscall, errno types.Errno) *metricVal {
	mu.RLock()
	defer mu.RUnlock()

	return m[mkaggMetricKey(container, sc, errno)]
}

func (m aggMetrics) lookupOrCreate(container *types.Container, sc *syscalls.Syscall, errno types.Errno) *metricVal {
	if container == nil {
		return nil
	}

	mu.Lock()
	defer mu.Unlock()

	key := mkaggMetricKey(container, sc, errno)
	if val, ok := m[key]; ok {
		return val
	}

	nval := newAggMetricVal(key)
	m[key] = nval
	return nval

}

var cmdTop = &cobra.Command{
	Use:   "top",
	Short: "terminal-based top thingy",
	Run: func(cmd *cobra.Command, args []string) {
		log.SetLevel(log.PanicLevel)

		crisock, err := cmd.Flags().GetString("cri")
		if err != nil {
			log.Fatal(err)
		}

		altroot, err := cmd.Flags().GetString("altroot")
		if err != nil {
			log.Fatal(err)
		}

		kconfig, err := cmd.Flags().GetString("kubeconfig")
		if err != nil {
			log.Fatal(err)
		}

		if kconfig == "" {
			kconfig = os.Getenv("HOME") + "/.kube/config"
		}

		labelSelector, err := cmd.Flags().GetString("label-selector")
		if err != nil {
			log.Fatal(err)
		}

		namespace, err := cmd.Flags().GetString("namespace")
		if err != nil {
			log.Fatal(err)
		}

		noui, err := cmd.Flags().GetBool("no-ui")
		if err != nil {
			log.Fatal(err)
		}

		if aggHosts, err := cmd.Flags().GetBool("aggregate-hosts"); err == nil {
			aggregateHosts = aggHosts
		}

		observer, err := topology.NewKubernetes(
			topology.WithKubernetesConfig(kconfig),
			topology.WithKubernetesCRI(crisock),
			topology.WithKubernetesNamespace(namespace),
			topology.WithKubernetesProcRoot(altroot),
			topology.WithKubernetesLabelSelector(labelSelector),
			topology.WithKubernetesFieldSelector("status.phase=Running"),
		)
		if err != nil {
			log.Fatal(err)
		}

		ctx := context.Background()
		bpf := assets.LoadBPFReader()

		hub, err := topology.NewHub(bpf, observer)
		if err != nil {
			log.Fatal(err)
		}

		if err := hub.Probe().DetectAndSetOffsets(); err != nil {
			log.Fatalf("Could not detect offsets for running kernel: %v", err)
		}

		go hub.MustRun(ctx)

		topo := hub.Topology()
		aggr := newAggMetrics()
		ktrics := metrics.NewHandler(hub.Probe().Module())
		tick := time.NewTicker(time.Second)

		if !noui {
			ui.Init()
			defer ui.Close()
		}

		swin := newAggregateWidget(&aggr)
		grid := ui.NewGrid()

		averages := make(map[string]*fixedRateArray)

		averages["syscall.errors"] = newFixedRateArray(30)
		averages["syscall.totals"] = newFixedRateArray(30)

		if !noui {
			grid.Set(
				ui.NewRow(1,
					ui.NewCol(1, swin),
				),
			)

			w, h := ui.TerminalDimensions()
			grid.SetRect(0, 0, w, h)
		}

		for {
			select {
			case <-tick.C:
				for _, unit := range ktrics.QueryAll() {
					cinfo, err := topo.LookupContainer(ctx, unit.PidNamespace())
					if err != nil {
						continue
					}

					count := float64(unit.Count())
					scall := syscalls.Lookup(int(unit.Syscall()))
					errno := types.Errno(unit.Errno())

					val := aggr.lookupOrCreate(cinfo, scall, errno)
					diff := count - val.count.Count()

					val.count.Inc(diff)
					val.rate.Mark(int64(diff))

				}

				totals := aggr.mergeStatsByKey(false)
				errors := aggr.mergeStatsByKey(true)

				averages["syscall.totals"].push(totals[metricKey{}].rate.RateMean())
				averages["syscall.errors"].push(errors[metricKey{}].rate.RateMean())

				if !noui {
					ui.Render(grid)
				}
			case ev, ok := <-ui.PollEvents():
				if !ok {
					return
				}

				switch ev.ID {
				case "q", "<C-c>":
					return
				}
			case <-ctx.Done():
				return
			}
		}

	},
}

type kubeTopWidget struct {
	*widgets.Table
	grid *ui.Grid
}

type syscMetrics struct {
	registry *gometrics.Registry
}

func init() {
	rootCmd.AddCommand(cmdTop)
	cmdTop.Flags().StringP("namespace", "n", "", "namespace to read from")
	cmdTop.Flags().StringP("output", "o", "cli", "output format")
	cmdTop.Flags().StringP("label-selector", "l", "", "label selector")
	cmdTop.Flags().Bool("aggregate-hosts", false, "Aggregate hosts to <container>.<pod>.<namespace>")
	cmdTop.Flags().Bool("no-ui", false, "disable UI")
}
