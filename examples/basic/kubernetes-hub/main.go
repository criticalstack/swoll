package main

import (
	"context"
	"fmt"
	"os"

	"github.com/criticalstack/swoll/api/v1alpha1"
	"github.com/criticalstack/swoll/pkg/event"
	"github.com/criticalstack/swoll/pkg/kernel/assets"
	"github.com/criticalstack/swoll/pkg/topology"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

func dumpTextEvent(name string, ev *event.TraceEvent) {
	fmt.Printf("job-id:%s - %s: [%s/%v] (%s) %s(", name, ev.Container.FQDN(), ev.Comm, ev.Pid, ev.Error, ev.Argv.CallName())
	for _, arg := range ev.Argv.Arguments() {
		fmt.Printf("(%s)%s=%v ", arg.Type, arg.Name, arg.Value)
	}
	fmt.Println(")")
}

func main() {
	log.SetOutput(os.Stderr)
	log.SetLevel(log.DebugLevel)

	// The first step, as always, is to load the BPF object.
	//
	// If you do not wish to ship the compiled BPF around with your code, swoll
	// contains a pre-compiled version of the BPF which can be loaded via
	// the assets API
	bpf := assets.LoadBPFReader()
	ctx := context.Background()

	dumpEvent := func(traceName string, ev *event.TraceEvent) {
		fmt.Printf("job-id:%s - %s: [%s/%v] (%s) %s(", traceName,
			ev.Container.FQDN(), ev.Comm, ev.Pid, ev.Error,
			ev.Argv.CallName(),
		)

		for _, arg := range ev.Argv.Arguments() {
			fmt.Printf("(%s)%s=%v ", arg.Type, arg.Name, arg.Value)
		}
		fmt.Println(")")
	}

	// Since the point of this example is to show how to "properly" use the
	// swoll API to monitor Kubernetes, we must start with the concept of a
	// the `topology`.
	//
	// The `topology` is a combination of an `Observer` and a `Hub`. The
	// `Observer` is an API which reads start and stop events from a container
	// runtime, and a `Hub` maintains the kernel-level filters for one or more trace
	// definitions using information obtained from the `Observer`.
	//
	// Using this combination of APIs has some unique properties which assist in
	// creating a performant analysis tool:
	// - All the hard work of maintaining the filters being run in the kernel is
	//   done for you.
	// - A single instance of the probe can run multiple traces at one time,
	//   only targetting the very specific pieces of information (e.g., filters
	//   for specific container/syscalls) which was requested.
	//
	//   This reduces the overhead of BPF code running in the kernel,
	//   as we only need a single tracepoint attached and running our filters.
	//
	// - Rule de-duplication. If you specify more than one rule, and the rule
	//   from the second has containers and system-calls that also matched the
	//   first, the kernel still only uses a single filter. The data is
	//   dynamically copied to the output of the second rule from the first.
	//
	//   It should be noted that the actual kernel filters are never removed
	//   until ALL rules which reference that filter are removed.
	//
	//   Secondary note: if the user has marked a rule as "sampled", and there
	//   is another rule which matches pods/containers from this rule, the
	//   lowest sample-rate is used in the kernel, and higher rates are
	//   sub-sampled in userland.
	// - A more kubernetes-like experience: everything can be done in Yaml if
	//   needed. Just like Kubernetes!
	//
	// First, we create the `Observer`, in our case, the Kubernetes observer. Under the
	// hood, this will use the k8s-api-server in combination with the CRI to
	// maintain the topology of all containers running in PODs.
	kubeObserver, err := topology.NewKubernetes(
		// Here you can tell the observer to use a specific Kubernetes
		// configuration file. If either this option is not passed, or the
		// argument to this option is empty, we assume that this is running
		// "in-cluster" or inside an already-running kubernetes cluster. I left
		// it in here as an example, but normally would be omitted when running
		// inside kube.
		topology.WithKubernetesConfig(""),
		// Specify the CRI socket to read container events from. This must be
		// the CRI socket as seen on the host it is running on. Make sure that
		// this file is available to this program.
		topology.WithKubernetesCRI("/run/containerd/containerd.sock"),
		// By default, the topology reader will see all containers in all
		// namespaces, set this to whatever namespace if you wish to limit the
		// search to a single namespace. It's usually a good idea to leave this
		// empty for the Observer.
		topology.WithKubernetesNamespace(""),
		// The observer does some checks for information contained in the ProcFS
		// directory (e.g., /proc), but if you have mounted this into a
		// different directory, you can specify that here. I'm leaving it here
		// as an example. This will lookup information from "/proc".
		topology.WithKubernetesProcRoot("/"),
		// You can optionally specify a set of labels to filter on using
		// `key=value` strings. Here we apply a filter which matches on any
		// pods/containers that do NOT have the label `noSwoll` set to
		// `true`. In other words, if a POD/container is created with the label
		// `noSwoll=true`, it will not be seen by this observer.
		topology.WithKubernetesLabelSelector("noSwoll!=true"),
		// Much like the label-selector, one can also add a Field Selection to
		// match on runtime information like the running status of the pod or
		// container. This is runtime specific, and in this case, we match only
		// hosts that Kubernetes has deemed as "Running".
		topology.WithKubernetesFieldSelector("status.phase=Running"),
	)
	if err != nil {
		log.Fatalf("Could not create the kubernetes observer: %v", err)
	}

	// Next we create our `Hub` which inherits our kubernetes observer. This
	// will initialize all the underlying BPF and apply initial kernel filters.
	// This API is the component which manipulates and maintains all of the
	// moving parts of the topology. It acts as a kernel event multiplexer.
	hub, err := topology.NewHub(bpf, kubeObserver)
	if err != nil {
		log.Fatalf("Could not create the topology hub: %v", err)
	}

	// Since we are using the pre-compiled BPF object, we must inform the kernel
	// BPF where to look inside our task_struct for various members that are not
	// known at runtime. Here we use a builtin helper function which determines,
	// and sets those offsets for us.
	if err := hub.Probe().DetectAndSetOffsets(); err != nil {
		log.Fatalf("Could not detect offsets for running kernel: %v", err)
	}

	// Start our Hub as a background task. This maintains a running list of all
	// containers and submitted jobs running on the system along with kernel filters,
	// garbage-collection, and other various house-keeping operations.
	go hub.MustRun(ctx)

	// Now in order to run one or more traces on the Hub, we must construct a properly
	// formatted TraceSpec for each trace we wish to install.
	//
	// This is a helper function to convert a string to a kubernetes LabelSet
	convertLabels := func(lstr string) labels.Set {
		ret, err := labels.ConvertSelectorToLabelsMap(lstr)
		if err != nil {
			log.Fatalf("Could not convert labels %v to labels map: %v", err)
		}
		return ret
	}

	// This first trace specification will trace the system-calls "openat",
	// "connect", "execve", and "accept4" for any *running* containers in the `swoll`
	// namespace that have the Kubernetes label `app=nginx` set.
	trace1 := &v1alpha1.Trace{
		ObjectMeta: metav1.ObjectMeta{
			// The Kubernetes namespace we want to monitor inside of. For this
			// example it is assumed that the deploy.yaml file in this directory
			// has been applied.
			Namespace: "swoll-hub-test",
		},
		Spec: v1alpha1.TraceSpec{
			LabelSelector: metav1.LabelSelector{
				// Monitor any hosts that have the `app=nginx` label
				// This should match some containers defined in the
				// `deploy.yaml` file found in this directory.
				MatchLabels: convertLabels("app=nginx"),
			},
			FieldSelector: metav1.LabelSelector{
				// Only monitor hosts that are currently up and running.
				MatchLabels: convertLabels("status.phase=Running"),
			},
			Syscalls: []string{"execve", "openat", "connect", "accept4"},
		},
		Status: v1alpha1.TraceStatus{
			// Set the name of this trace, can be anything; if left empty, a
			// name will be generated.
			JobID: "trace1-monitor-nginx",
		},
	}

	// This second trace specification will monitor `execve` calls for any
	// running container in any kubernetes namespace.
	trace2 := &v1alpha1.Trace{
		ObjectMeta: metav1.ObjectMeta{
			// An empty namespace means to monitor ALL namespaces
			Namespace: "",
		},
		Spec: v1alpha1.TraceSpec{
			FieldSelector: metav1.LabelSelector{
				// Only monitor hosts that are currently up and running.
				MatchLabels: convertLabels("status.phase=Running"),
			},
			Syscalls: []string{"execve"},
		},
		Status: v1alpha1.TraceStatus{
			// Set the name of this trace, can be anything; if left empty, a
			// name will be generated.
			JobID: "trace2-monitor-execve",
		},
	}

	// Next we submit and run these two trace specifications in our Hub as a
	// background task
	go hub.RunTrace(ctx, trace1)
	go hub.RunTrace(ctx, trace2)

	// And now for the final step: attaching to the two running traces and
	// printing out the output of each. The second argument of these calls it
	// the callback function to execute for every event that matched.
	hub.AttachTrace(trace1, dumpTextEvent)
	hub.AttachTrace(trace2, dumpTextEvent)

	// If you have used the deploy.yaml found within this directory, you will
	// see two `job-id`'s firing:
	//
	//  `trace1-monitor-nginx`
	//  `trace2-monitor-execve`
	//
	// Since `trace1` monitors execve for only a subset of hosts (`app=nginx`), and `trace2`
	// monitors ALL execve calls across all hosts, both rules will fire for
	// TraceEvent's sourced from hosts with the label `app=nginx`.
	//
	// This is an example of how the Hub
	// does de-duplication.

	// Run until we are told to stop.
	<-ctx.Done()
}
