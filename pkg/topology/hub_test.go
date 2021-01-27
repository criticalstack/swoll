package topology

import (
	"context"

	"github.com/criticalstack/swoll/api/v1alpha1"
	"github.com/criticalstack/swoll/pkg/event"
	"github.com/criticalstack/swoll/pkg/kernel/assets"
)

// Running the Hub
func ExampleHub_Run() {
	obs, err := topology.NewKubernetes()
	if err != nil {
		panic(err)
	}

	hub, err := topology.NewHub(assets.LoadBPFReader(), obs)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	go hub.Run(ctx)
	<-ctx.Done()
}

// A short example showing how to use the RunTrace call
func ExampleHub_RunTrace() {
	hub, err := topology.NewHub(bpf, observer)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()

	// Run the Hub.
	go hub.MustRun(ctx)

	// Monitor execve and openat in the kubernetes-namespace 'kube-system' and
	// name the job "foo-bar".
	go hub.RunTrace(ctx, &v1alpha1.Trace{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system",
		},
		Spec: v1alpha1.TraceSpec{
			Syscalls: []string{"execve", "openat"},
		},
		Status: v1alpha1.TraceStatus{
			JobID: "foo-bar",
		},
	})

	// trace is now running inside the Hub, you must attach to it to recv events
	<-ctx.Done()

}

// Simple example to show how to use the AttachTrace method, this assumes the
// topology.Hub is already running with an Observer.
func ExampleHub_AttachTrace() {
	trace := &v1alpha1.Trace{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-system",
		},
		Spec: v1alpha1.TraceSpec{
			Syscalls: []string{"execve", "openat"},
		},
		Status: v1alpha1.TraceStatus{
			JobID: "foo-bar",
		},
	}

	go hub.RunTrace(ctx, trace)
	hub.AttachTrace(trace, func(name string, ev *event.TraceEvent) {})
}

// In this example we use AttachPath to "subscribe" to a subset of events being
// sent to a running Job output.
func ExampleHub_AttachPath() {
	// Assumes there is a job that has matches namespace=kube-system,
	// pod=foo-pod, and a container named "boo"
	unsub := hub.AttachPath("example", []string{"kube-system", "foo-pod", "boo"},
		func(name string, ev *event.TraceEvent) {})
	defer unsub()
}
