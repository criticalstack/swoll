package hub

import (
	"container/list"
	"context"
	"log"
	"time"

	"github.com/criticalstack/swoll/api/v1alpha1"
	"github.com/criticalstack/swoll/internal/pkg/pubsub"
	"github.com/criticalstack/swoll/pkg/event"
	"github.com/criticalstack/swoll/pkg/event/reader"
	"github.com/criticalstack/swoll/pkg/syscalls"
	"github.com/criticalstack/swoll/pkg/topology"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Job maintains the general rules for which a trace runs under.
type Job struct {
	*v1alpha1.Trace
	sampled        int
	emulateSamples bool
	monitoredHosts map[string]bool
}

// JobContext is a structure that is used to store all the kernel filtering
// information per pid-namespace.
//
// When we reference a "POD" in this code, we use the PID namespace of the
// underlying container to key off of. Since multiple jobs can have some of
// the same syscalls and hosts being monitored, we create a list of all possible
// rules, but only filter in the kernel what is needed.
//
// For example: say we have two "jobs". "Job-A", and "Job-B".
// Job-A monitors "app=nginx" with the syscalls "open"/"close"
// Job-B monitors "type=webserver" with the syscalls "open"
//   app=nginx matches 'host-A' and 'host-B'
//   type=webserver matches 'host-A' and 'host-Z'
// If we were to blindly delete Job-B, (meaning removing the filters for
// 'Host-A' and syscall "open"), we would also delete the filter that is
// being used for 'Job-A'. So we just make sure we don't delete from the
// actual kernel filter until our lists are empty.
type JobContext struct {
	*Job
	// the element that was used for insertion into the `nsmap` in `Hub`
	nselem *list.Element
	// the element that was used for insertion into the `idmap` in `Hub`
	idelem *list.Element
	// the pid namespace and syscall-nr for this specific context
	nr, ns int
}

// JobList is a wrapper around a simple linked-list for groups of JobContexts
type JobList struct {
	*list.List
}

// createJobKey generates a formatted key to use with container additions
func createJobKey(pod, name string) string {
	return name + "." + pod
}

// AddContainer tells the job to monitor a very specific container in a specific
// pod.
func (j *Job) AddContainer(pod, name string) {
	key := createJobKey(pod, name)

	if _, ok := j.monitoredHosts[key]; ok {
		return
	}

	j.monitoredHosts[key] = true
}

// RemoveContainer removes the watch for a specific container in a specific pod
func (j *Job) RemoveContainer(pod, name string) {
	j.monitoredHosts[createJobKey(pod, name)] = false
}

// Run will run a job inside the Hub. The primary goal of this function is to
// read topology events using the LabelMatch, and for each pod that matches,
// create the kernel filter if needed, and append the JobContext to the list
// of running jobs in the Hub.
func (j *Job) Run(ctx context.Context, h *Hub) error {
	now := metav1.NewTime(time.Now())
	j.Status.StartTime = &now

	spec := j.TraceSpec()
	kubetop, err := topology.NewKubernetes(
		topology.WithKubernetesCRI(h.config.CRIEndpoint),
		topology.WithKubernetesConfig(h.config.K8SEndpoint),
		topology.WithKubernetesNamespace(j.Namespace),
		topology.WithKubernetesProcRoot(h.config.AltRoot),
		topology.WithKubernetesLabelSelector(labels.Set(spec.LabelSelector.MatchLabels).String()),
		topology.WithKubernetesFieldSelector(labels.Set(spec.FieldSelector.MatchLabels).String()))
	if err != nil {
		log.Fatal(err)
	}

	topo := topology.NewTopology(kubetop)
	rdr := reader.NewEventReader(topo)
	//nolint:errcheck
	go rdr.Run(ctx)

	// these are the list of syscalls which will be used as rules for each
	// matched container from the topology api.
	calls := make(syscalls.SyscallList, 0)
	for _, sc := range spec.Syscalls {
		calls = append(calls, syscalls.Lookup(sc))
	}

	// It should be noted that we are looking at topology events, meaning these
	// are messages informing us about containers entering and leaving the
	// cluster. So when you see kernel filters being added and removed, even if
	// associated with another job, these are containers that have left or
	// joined the cluster so they need to be removed from the filter.
	for {
		select {
		case ev := <-rdr.Read():
			switch ev := ev.(type) {
			case event.ContainerAddEvent:
				// new container found inside cluster that matched our labels
				name := ev.Name

				if len(spec.HostSelector) > 0 {
					// if we have a host-selector array in our spec, attempt to
					// match this container's name with the entries in this
					// variable. Only if they match will the filter be added.
					matched := false
					for _, h := range spec.HostSelector {
						if h == name {
							matched = true
							break
						}
					}

					if !matched {
						// just break out of this case if we didn't match
						// anything
						break
					}

				}

				pns := ev.PidNamespace
				j.AddContainer(ev.Pod, name)

				// got a new container that matched, for each syscall, push a
				// job up that associates pidns+syscallNR with this job
				for _, sc := range calls {
					log.Printf("[%s/%d] Adding syscall '%s' to kernel-filter\n", j.JobID(), pns, sc.Name)

					// This will create a sub-filter off of the pid-namespace
					// which matches this subset of syscalls..
					h.PushJob(j, pns, sc.Nr)

					// Tell the kernel that we wish to monitor this syscall for
					// this given pid-namespace.
					// Note: if the filter already exists, this acts as a NOP.
					if err := h.filter.AddSyscall(sc.Nr, pns); err != nil {
						log.Printf("[%s/%d] Error adding syscall kernel-filter for '%s'\n", j.JobID(), pns, sc.Name)
						return err
					}
				}

			case event.ContainerDelEvent:
				// container that matched our labels is being removed from the
				// cluster. Knowing that this container no longer exists, we
				// can remove the associated global kernel filters.
				pns := ev.PidNamespace
				j.RemoveContainer(ev.Pod, ev.Name)

				for _, sc := range calls {
					log.Printf("[%s/%d] removing syscall '%s' to kernel-filter\n", j.JobID(), pns, sc.Name)

					if err := h.filter.RemoveSyscall(sc.Nr, pns); err != nil {
						log.Printf("[%s/%d] failed to remove syscall '%s' from kernel-filter\n", j.JobID(), pns, sc.Name)

						// XXX[lz]: just continue on for now - but we should
						// really think about what to do in cases like this as
						// it might be dire.
					}
				}
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// WriteEvent writes event `ev` to all listeners of this `Job`
func (j *Job) WriteEvent(h *Hub, ev *event.TraceEvent) {
	if j.Spec.SampleRate > 0 {
		// if this job is marked as sampled, and there are other jobs running
		// that are sampling at a different rate for the same data from the
		// kernel, we must emulate the rate in which was requested for this
		// specific rule.
		//
		// we do this by finding the lowest-sample config value for this
		// pid_namespace+syscall_nr configured in the kernel. We create a
		// sub-sample value based off this returned value and this job's sample
		// rate so that sampling-a-sample will be statistically correct.
		//
		// For example, if we have 8 events, e1...e8, and three rules which
		// match the same host+syscall,
		// r1: sample=1 // 1:1 sampling, e.g., ALL
		// r2: sample=2
		// r3: sample=4
		//
		// r1 will match on e1,e2,e3,e4,e5,e6,e7,e8 (kernel sampled)
		// r2 will match on e2,e4,e6,e8             (emulated sampled)
		// r3 will match on e4,e8                   (emulated sampled)
		j.sampled++

		// find the job context for this specific namespace and syscall-nr that
		// has the lowest sample-rate.
		jctx := h.findLowestSampleJob(ev.PidNamespace, ev.Syscall.Nr)
		if jctx.Job == j {
			// this job is the holder of the lowest sample rate.
			// so we can calculate the sub-sample value directly using this jobs
			// rate.
			if j.sampled%j.Spec.SampleRate == 0 {
				log.Printf("[%s] job is already lowest sample-rate, Sending sampled %d\n", j.JobID(), j.sampled)
				h.ps.Publish(ev, pubsub.LinearTreeTraverser(hashPath(swJobStream, j.JobID())))
			}
		} else {
			// this job is NOT the holder of the lowest sample rate. So we
			// subtract the lowst known sample rate from this sample rate to
			// create a subsample value.
			subsample := j.Spec.SampleRate - jctx.Spec.SampleRate
			if j.sampled%subsample == 0 {
				log.Printf("[%s] job is a sub-sample, sending %d\n", j.JobID(), j.sampled)
				h.ps.Publish(ev, pubsub.LinearTreeTraverser(hashPath(swJobStream, j.JobID())))
			}
		}
	} else {
		log.Printf("[%s] job has no sample-rate, Sending %d\n", j.JobID(), j.sampled)
		h.ps.Publish(ev, pubsub.LinearTreeTraverser(hashPath(swJobStream, j.JobID())))
	}
}

// TraceSpec returns the `TraceSpec` defined for this `Job`
func (j *Job) TraceSpec() *v1alpha1.TraceSpec {
	if j != nil {
		return &j.Spec
	}

	return nil
}

// TraceStatus returns the status of this Job
func (j *Job) TraceStatus() *v1alpha1.TraceStatus {
	if j != nil {
		return &j.Status
	}

	return nil
}

// JobID returns the raw job-id associated with this job
func (j *Job) JobID() string {
	if s := j.TraceStatus(); s != nil {
		return s.JobID
	}

	return ""
}

// Duration returns how long this job has been running as seen by kube.
func (j *Job) Duration() time.Duration {
	if s := j.TraceSpec(); s != nil {
		return s.Duration.Duration
	}

	return -1
}

// MonitoredHosts returns a list of hosts that have been monitored by this job.
// If `all` is `false`, then ony containers that are currently being monitored
// will return, otherwise it will return every host that has ever matched this
// job.
func (j *Job) MonitoredHosts(all bool) []string {
	ret := []string{}

	for k, v := range j.monitoredHosts {
		// `all` is false, and if the value of this is false, then don't add it.
		if !all && !v {
			continue
		}
		ret = append(ret, k)
	}

	return ret
}

// NewJob returns a Job for the trace
func NewJob(t *v1alpha1.Trace) *Job {
	return &Job{
		Trace:          t,
		monitoredHosts: make(map[string]bool),
	}
}
