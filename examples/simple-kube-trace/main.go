package main

import (
	"context"
	"fmt"
	"log"

	"github.com/criticalstack/swoll/pkg/event"
	"github.com/criticalstack/swoll/pkg/event/call"
	"github.com/criticalstack/swoll/pkg/kernel"
	"github.com/criticalstack/swoll/pkg/kernel/assets"
	"github.com/criticalstack/swoll/pkg/kernel/filter"
	"github.com/criticalstack/swoll/pkg/topology"
	"github.com/criticalstack/swoll/pkg/types"
)

func dumpTextEvent(ev *event.TraceEvent) {
	fn := ev.Argv.(call.Function)

	fmt.Printf("%s: [%s/%v] (%s) %s(", ev.Container.FQDN(), ev.Comm, ev.Pid, ev.Error, fn.CallName())
	for _, arg := range fn.Arguments() {
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

	f, err := filter.NewFilter(probe.Module())
	if err != nil {
		log.Fatalf("Unable to create filter: %v", err)
	}

	f.FilterSelf()
	f.AddSyscall("execve", -1)
	f.AddSyscall("openat", -1)
	f.AddSyscall("accept4", -1)
	f.AddSyscall("connect", -1)

	kubeTopo, err := topology.NewKubernetes(topology.WithKubernetesCRI("/run/containerd/containerd.sock"))
	if err != nil {
		log.Fatalf("Unable to create topology context: %v", err)
	}

	ctx := context.Background()
	topo := topology.NewTopology(kubeTopo)
	event := new(event.TraceEvent).WithTopology(topo)

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
