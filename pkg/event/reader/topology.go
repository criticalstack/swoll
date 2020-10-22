package reader

import (
	"context"

	"github.com/criticalstack/swoll/pkg/event"
	"github.com/criticalstack/swoll/pkg/topology"
	"github.com/criticalstack/swoll/pkg/types"
)

type TopologyReader struct {
	topo    *topology.Topology
	backlog chan interface{}
}

func NewTopologyReader(t *topology.Topology) EventReader {
	return &TopologyReader{t, make(chan interface{})}
}

func (t *TopologyReader) Read() chan interface{} {
	return t.backlog
}

func (t *TopologyReader) handler(tp topology.EventType, c *types.Container) {
	switch tp {
	case topology.EventTypeStart:
		t.backlog <- event.ContainerAddEvent{Container: c}
	case topology.EventTypeStop:
		t.backlog <- event.ContainerDelEvent{Container: c}
	}
}

func (t *TopologyReader) Run(ctx context.Context) error {
	t.topo.Run(ctx, t.handler)
	return nil
}
