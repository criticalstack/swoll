// Package topology is the preferred method for creating and supervising system
// traces when using the Swoll API on modern container management and
// orchestration systems such as Kubernetes.
//
// To better understand what this package does, it is best to start with
// learning a little bit about how Swoll creates, captures, filters, and
// emits data from the kernel back into our code.
//
// The Swoll BPF has a very simple userspace-configurable filtering mechanism
// which allows us to either white-list or black-list what syscalls we want to
// monitor. Optionally, each call we want to monitor can also be associated with
// a specific kernel namespace. So, for example, a user can request to only see
// events which made the sytem call "open" in the kernel PID-Namespace `31337`.
// Any events that do not match this specific rule will be silently dropped by
// the kernel.
//
// Furthermore, each filter can optionally maintain a basic sample-rate
// configuration, giving the developer the option to gain insight into high-load
// system-calls such as `sys_read` without impacting performance too much.
//
// Since each container within a `Pod` gets its own unique (or derived if
// shared) namespace, swoll exploits the above ns+syscall filter feature by
// maintaining the relations between Kubernetes and the container-runtime by
// dynamically updating and tuning the filters in real-time.
//
// In short (using Kubernetes as an example), when we request Swoll to monitor
// syscall events for the Pod "foobar", we connect to the kube-api-server, watch
// for Pod events that match "foobar", and when matched, utilizes the Container
// Runtime Interface to find process details for that Pod. Once we have obtained
// the init PID from the CRI, we can render the PID namespace we need to use to
// set the filter in the kernel.
//
// In theory this sounds simple, but in practice things are not as easy. Swoll
// strives to run as lean-and-mean as possible, and in doing so, the goal
// of which is "One BPF Context To Mon Them All", and still without sacrificing
// performance for flexibility or vice-versa.
//
// And the Topology API is exactly that. It "observes" events from Kubernetes
// and CRI (see: topology.Observer), runs one or more v1alpha1.Trace specifications as a
// topology.Job, which in-turn dynamically updates, de-duplicates,
// and prunes the kernel filter inside a single BPF context, better known as the
// topology.Hub.
package topology
