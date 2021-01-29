package topology

import (
	"container/list"
	"context"
	"time"

	"github.com/criticalstack/swoll/api/v1alpha1"
	"github.com/criticalstack/swoll/internal/pkg/pubsub"
	"github.com/criticalstack/swoll/pkg/event"
	"github.com/criticalstack/swoll/pkg/syscalls"
	"github.com/criticalstack/swoll/pkg/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Job stores the trace specification and a running list of hosts which have
// matched this job.
type Job struct {
	*v1alpha1.Trace
	sampled        int
	monitoredHosts map[string]bool
}

// JobContext contains information about the filters that were created in order
// to run a Job. Since multiple jobs can have shared resources (like
// kernel-filters), all possible rules are created and set.
//
// For example, say we have two jobs: "job-A", and "job-B".
//
//  job-A monitors pods that match the label: app=nginx for the syscalls: "open", and "close"
//  job-B monitors pods that match the label: type=webserver for just the syscall "open"
//
// If a pod was created with both the labels above (app=nginx,type=webserver),
// and we were to blindly delete "job-B", any filters that were added that
// matched both rules would be removed.
//
// Thus every filter is accounted for, treated much like a reference counter,
// only removing from the kernel-filter when no rules require it.
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

	// grab the trace specification from this job definition.
	spec := j.TraceSpec()

	// derive an Observer using the parent observer (most likely the Kubernetes observer), but
	// set the namespace and various selectors to match this job.
	observer, err := h.topo.observer.Copy(
		WithKubernetesNamespace(j.Namespace),
		WithKubernetesLabelSelector(labels.Set(spec.LabelSelector.MatchLabels).String()),
		WithKubernetesFieldSelector(labels.Set(spec.FieldSelector.MatchLabels).String()))
	if err != nil {
		return errors.Wrapf(err, "could not make a copy of the observer")
	}

	// these are the list of syscalls which will be used as rules for each
	// matched container from the topology api.
	calls := make(syscalls.SyscallList, 0)
	for _, sc := range spec.Syscalls {
		calls = append(calls, syscalls.Lookup(sc))
	}

	// Create and run the topology using the new Observer for this specific job.
	go NewTopology(observer).Run(ctx, func(etype EventType, c *types.Container) {
		switch etype {
		case EventTypeStop:
			// container that matched our labels is being removed from the
			// cluster. Knowing that this container no longer exists, we
			// can remove the associated global kernel filters.
			pns := c.PidNamespace
			j.RemoveContainer(c.Pod, c.Name)

			for _, sc := range calls {
				log.Tracef("[%s/%d] removing syscall '%s' to kernel-filter\n", j.JobID(), pns, sc.Name)

				if err := h.filter.RemoveSyscall(sc.Nr, pns); err != nil {
					log.Warnf("[%s/%d] failed to remove syscall '%s' from kernel-filter\n", j.JobID(), pns, sc.Name)

					// XXX[lz]: just continue on for now - but we should
					// really think about what to do in cases like this as
					// it might be dire.
				}
			}
		case EventTypeStart:
			// new container found inside cluster that matched our labels
			name := c.Name

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

			pns := c.PidNamespace
			j.AddContainer(c.Pod, name)

			// got a new container that matched, for each syscall, push a
			// job up that associates pidns+syscallNR with this job
			for _, sc := range calls {
				log.Tracef("[%s/%d] Adding syscall '%s' to kernel-filter\n", j.JobID(), pns, sc.Name)

				// This will create a sub-filter off of the pid-namespace
				// which matches this subset of syscalls..
				h.PushJob(j, pns, sc.Nr)

				sampleRate := spec.SampleRate

				if sampleRate > 0 {
					// find the job with the lowest current sampleRate, and
					// if it is lower than this job's sampleRate, replace it
					// with this one. The other job's will emulate via
					// sub-sampling the true samplerate.
					if lowestJob := h.findLowestSampleJob(sc.Nr, pns); lowestJob != nil && lowestJob.Spec.SampleRate < sampleRate {
						log.Tracef("[%s/%d] swapping sample-rate for currently running rule to %d\n", j.JobID(), pns, sampleRate)
						if err := h.filter.RemoveSyscall(sc.Nr, pns); err != nil {
							log.Warnf("Couldn't remove syscall %v\n", err)
						}
					}

					if err := h.filter.AddSampledSyscall(sc.Nr, pns, uint64(sampleRate)); err != nil {
						log.Warnf("[%s/%d] Error adding syscall kernel-filter for '%s'\n", j.JobID(), pns, sc.Name)
						return
					}
				}

				// Tell the kernel that we wish to monitor this syscall for
				// this given pid-namespace.
				// Note: if the filter already exists, this acts as a NOP.
				if err := h.filter.AddSyscall(sc.Nr, pns); err != nil {
					log.Warnf("[%s/%d] Error adding syscall kernel-filter for '%s'\n", j.JobID(), pns, sc.Name)
					return
				}
			}
		}
	})

	<-ctx.Done()
	return nil
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
				log.Tracef("[%s] job is already lowest sample-rate, Sending sampled %d\n", j.JobID(), j.sampled)
				h.ps.Publish(ev, pubsub.LinearTreeTraverser(hashPath(swJobStream, j.JobID())))
			}
		} else {
			// this job is NOT the holder of the lowest sample rate. So we
			// subtract the lowst known sample rate from this sample rate to
			// create a subsample value.
			subsample := j.Spec.SampleRate - jctx.Spec.SampleRate
			if j.sampled%subsample == 0 {
				log.Tracef("[%s] job is a sub-sample, sending %d\n", j.JobID(), j.sampled)
				h.ps.Publish(ev, pubsub.LinearTreeTraverser(hashPath(swJobStream, j.JobID())))
			}
		}
	} else {
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
