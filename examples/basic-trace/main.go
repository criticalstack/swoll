package main

import (
	"context"
	"fmt"
	"log"

	"github.com/criticalstack/swoll/pkg/event"
	"github.com/criticalstack/swoll/pkg/event/call"
	"github.com/criticalstack/swoll/pkg/kernel"
	"github.com/criticalstack/swoll/pkg/kernel/assets"
)

func dumpTextEvent(ev *event.TraceEvent) {
	fn := ev.Argv.(call.Function)

	fmt.Printf("[%s/%v] (%s) %s(", ev.Comm, ev.Pid, ev.Error, fn.CallName())
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

	if err := probe.InitProbe(kernel.WithOffsetDetection(), kernel.WithDefaultFilter()); err != nil {
		log.Fatalf("Unable to initialize probe: %v", err)
	}

	event := new(event.TraceEvent)

	probe.Run(context.Background(), func(msg []byte, lost uint64) error {
		parsed, err := event.Ingest(msg)
		if err != nil {
			return nil
		}

		dumpTextEvent(parsed)

		return nil
	})
}
