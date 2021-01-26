// +build ignore
package main

import (
	"fmt"
	"log"

	"github.com/criticalstack/swoll/pkg/event"
	"github.com/criticalstack/swoll/pkg/kernel/assets"
)

func dumpTextEvent(ev *event.TraceEvent) {
	fmt.Printf("%s: [%s/%v] (%s) %s(", ev.Container.FQDN(), ev.Comm, ev.Pid, ev.Error, ev.Argv.CallName())
	for _, arg := range ev.Argv.Arguments() {
		fmt.Printf("(%s)%s=%v ", arg.Type, arg.Name, arg.Value)
	}
	fmt.Println(")")
}

func main() {
	// The first step, as always, is to load the BPF object.
	//
	// If you do not wish to ship the compiled BPF around with your code, swoll
	// contains a pre-compiled version of the BPF object which can be loaded via
	// the assets API
	bpf := assets.LoadBPF()

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
	//   only targetting the very specific pieces of information that was
	//   requested.
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
		// namespaces, this configuration tells the observer to only watch for
		// changes in the `kube-system` namespace.
		topology.WithKubernetesNamespace("kube-system"),
		// The observer does some checks for information contained in the ProcFS
		// directory (e.g., /proc), but if you have mounted this into a
		// different directory, you can specify that here. I'm leaving it here
		// as an example. This will lookup the information from "/proc".
		topology.WithKubernetesProcRoot("/"),
		// You can optionally specify a set of labels to filter on using
		// `key=value` strings. Here we apply a filter which matches on any
		// pods/containers that do NOT have the label `dont-swoll-me` set to
		// `true`. In other words, if a POD/container is created with the label
		// `dont-swoll-me=true`, it will not be seen by this observer.
		topology.WIthKubernetesLabelSelector("dont-swoll-me!=true"),
		// Much like the label-selector, one can also add a Field Selection to
		// match on runtime information like the running status of the pod or
		// container. This is runtime specific, and in this case, we match only
		// hosts that Kubernetes has deemed as "Running".
		topology.WithKubernetesFieldSelector("status.Phase=Running"),
	)
	if err != nil {
		log.Fatalf("Could not create the kubernetes observer: %v", err)
	}

	// Next we create our `Hub` which inherits our kubernetes observer. This
	// will initialize all the underlying BPF and apply initial kernel filters.
	// This API is the component which manipulates and maintains all of the
	// moving parts of the topology.
	//
	// Most of these arguments are the same as the `kubeObserver` configuration
	// options. In future releases these will be deprecated and completely co
	/*
		traceHub, err := hub.NewHub(&hub.Config{
			BPFObject: bpf,
		}
	*/

	/*
		// Next, we must create a probe object from our BPF code. In most cases, the
		// second argument (the base configuration) can be left as nil for the
		// default.
		probe, err := kernel.NewProbe(bpfCode, nil)
		if err != nil {
			log.Fatalf("Unable to create the kernel-probe context: %v", err)
		}

		// The next step involves initializing all of the underlying probe data, in
		// this specific case, we initialize with the `WithOffsetDetection` option.
		// Without going into too much detail, there are various members into the
		// `struct task_struct` kernel structure that swoll needs to access; Since
		// this can differ from kernel-to-kernel, when this option is passed, these
		// offsets are resolved via the currently running version.
		if err := probe.InitProbe(kernel.WithOffsetDetection()); err != nil {
			log.Fatalf("Unable to initialize probe: %v", err)
		}
	*/

	/*
		// Before we put this into a running mode, we (should) create a filter that
		// will be run inside the kernel. `NewFilter`'s first argument is the raw
		// BPF handle, as we want to interact with the filter for this specific BPF
		// context.
		f, err := filter.NewFilter(probe.Module())
		if err != nil {
			log.Fatalf("Unable to create filter: %v", err)
		}

		f.FilterSelf()
		f.AddSyscall("execve", -1)
		f.AddSyscall("openat", -1)
		f.AddSyscall("accept4", -1)
		f.AddSyscall("connect", -1)

		observer, err := topology.NewKubernetes(topology.WithKubernetesCRI("/run/containerd/containerd.sock"))
		if err != nil {
			log.Fatalf("Unable to create topology context: %v", err)
		}

		ctx := context.Background()
		topo := topology.NewTopology(observer)
		event := event.NewTraceEvent().WithTopology(topo)

		go topo.Run(ctx, func(tp topology.EventType, c *types.Container) {
			fmt.Printf("eventType=%v, container=%v\n", tp, c.FQDN())
		})

		probe.Run(ctx, func(msg []byte, lost uint64) error {
			parsed, err := event.Ingest(msg)
			if err != nil {
				return nil
			}

			dumpTextEvent(parsed)

			return nil
		})
	*/
}
