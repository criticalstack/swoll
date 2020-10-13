package reader

import (
	"context"
	"errors"

	"github.com/criticalstack/swoll/pkg/event"
	"github.com/criticalstack/swoll/pkg/podmon"
)

type PodmonReader struct {
	podmon  *podmon.PodMon
	backlog chan interface{}
}

func NewPodmonReader(pm *podmon.PodMon) EventReader {
	return &PodmonReader{pm, make(chan interface{})}
}

func (p *PodmonReader) Read() chan interface{} {
	return p.backlog
}

func (p *PodmonReader) handler(t podmon.UpdateType, c *podmon.CRIContainer) {
	switch t {
	case podmon.UpdateAdd:
		p.backlog <- event.PodmonAddEvent{CRIContainer: c}
	case podmon.UpdateDel:
		p.backlog <- event.PodmonDelEvent{CRIContainer: c}
	}
}

func (p *PodmonReader) Run(ctx context.Context) error {
	if p == nil {
		return errors.New("nil context")
	}

	return p.podmon.Run(ctx, p.handler)
}
