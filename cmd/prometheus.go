package cmd

import (
	"fmt"

	"github.com/criticalstack/swoll/pkg/kernel/metrics"
	"github.com/criticalstack/swoll/pkg/podmon"
	"github.com/criticalstack/swoll/pkg/syscalls"
	"github.com/criticalstack/swoll/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
)

type prometheusWorker struct {
	handler   *metrics.Handler
	podMon    *podmon.PodMon
	total     *prometheus.Desc
	timeSpent *prometheus.Desc
	syscalls  *syscalls.Syscalls
}

func newPrometheusWorker(handler *metrics.Handler, pmon *podmon.PodMon) *prometheusWorker {
	labels := []string{"syscall", "pod", "container", "namespace", "class", "group", "err", "kns"}

	syscalls, _ := syscalls.New()

	return &prometheusWorker{
		handler:  handler,
		podMon:   pmon,
		syscalls: syscalls,
		total: prometheus.NewDesc(
			prometheus.BuildFQName("syswall_node_metrics", "", "syscall_count"),
			"The total count for a given syscall.",
			labels,
			nil,
		),
		timeSpent: prometheus.NewDesc(
			prometheus.BuildFQName("syswall_node_metrics", "", "syscall_time"),
			"The time in nanoseconds spent executing a given syscall.",
			labels,
			nil,
		),
	}
}

func (w prometheusWorker) Describe(ch chan<- *prometheus.Desc) {
	ch <- w.total
	ch <- w.timeSpent
}

func (w prometheusWorker) Collect(ch chan<- prometheus.Metric) {
	if w.podMon == nil {
		// if we don't have a valid podmon context right now, just discard.
		// TODO[lz]: should we do non-resolved stats here?
		return
	}

	for _, metric := range w.handler.QueryAll() {
		container, err := w.podMon.Resolve(podmon.ResolverContext(metric))
		if err != nil {
			continue
		}

		scnr := metric.Syscall()
		errno := metric.Errno()
		count := metric.Count()
		spent := metric.TimeSpent()
		syscall := w.syscalls.Lookup(int(scnr))

		ch <- prometheus.MustNewConstMetric(
			w.total,
			prometheus.CounterValue,
			float64(count),
			syscall.Name,
			container.Pod, container.Name, container.Namespace,
			syscall.Class,
			syscall.Group,
			types.Errno(errno).String(),
			fmt.Sprintf("%v", metric.PidNamespace()),
		)

		ch <- prometheus.MustNewConstMetric(
			w.timeSpent,
			prometheus.CounterValue,
			float64(spent),
			syscall.Name,
			container.Pod, container.Name, container.Namespace,
			syscall.Class,
			syscall.Group,
			types.Errno(errno).String(),
			fmt.Sprintf("%v", metric.PidNamespace()),
		)
	}
}
