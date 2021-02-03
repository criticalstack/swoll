package main

import (
	"context"
	"fmt"
	"log"

	"github.com/criticalstack/swoll/pkg/event"
	"github.com/criticalstack/swoll/pkg/kernel"
	"github.com/criticalstack/swoll/pkg/kernel/assets"
	"github.com/criticalstack/swoll/pkg/topology"
	"github.com/criticalstack/swoll/pkg/types"
)

func dumpTextEvent(ev *event.TraceEvent) {
	fmt.Printf("%s: [%s/%v] (%s) %s(", ev.Container.FQDN(), ev.Comm, ev.Pid, ev.Error, ev.Argv.CallName())
	for _, arg := range ev.Argv.Arguments() {
		fmt.Printf("(%s)%s=%v ", arg.Type, arg.Name, arg.Value)
	}
	fmt.Println(")")
}

func main() {
	probe, err := kernel.NewProbe(assets.LoadBPFReader(), nil)
	if err != nil {
		log.Fatalf("Unable to load static BPF asset: %v", err)
	}

	if err := probe.InitProbe(kernel.WithOffsetDetection()); err != nil {
		log.Fatalf("Unable to initialize probe: %v", err)
	}

	filter := kernel.NewFilter(probe.Module())

	filter.FilterSelf()
	filter.AddSyscall("execve", -1)
	filter.AddSyscall("openat", -1)
	filter.AddSyscall("accept4", -1)
	filter.AddSyscall("connect", -1)

	observer, err := topology.NewKubernetes(topology.WithKubernetesCRI("/run/containerd/containerd.sock"))
	if err != nil {
		log.Fatalf("Unable to create topology context: %v", err)
	}

	ctx := context.Background()
	topo := topology.NewTopology(observer)
	event := event.NewTraceEvent().WithContainerLookup(
		func(ns int) (*types.Container, error) {
			return topo.LookupContainer(ctx, ns)
		})

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
}
