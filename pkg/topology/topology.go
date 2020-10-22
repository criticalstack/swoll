package topology

import (
	"context"
	"sync"

	"github.com/criticalstack/swoll/pkg/types"
	"github.com/pkg/errors"
)

type EventType int
type OnEventCallback func(t EventType, container *types.Container)

const (
	EventTypeStart EventType = iota
	EventTypeStop
)

var (
	ErrNilEvent          = errors.New("nil event")
	ErrNilContainer      = errors.New("nil container")
	ErrUnknownType       = errors.New("unknown event-type")
	ErrBadNamespace      = errors.New("invalid kernel pid-namespace")
	ErrContainerNotFound = errors.New("container not found")
)

type ObservationEvent struct {
	Type      EventType
	Container *types.Container
}

type Observer interface {
	Connect(ctx context.Context) error
	Containers(ctx context.Context) ([]*types.Container, error)
	Run(ctx context.Context, out chan<- *ObservationEvent)
	Close() error
}

type Topology struct {
	sync.RWMutex
	observer Observer
	cache    map[int]*types.Container
}

func NewTopology(obs Observer) *Topology {
	return &Topology{
		observer: obs,
		cache:    make(map[int]*types.Container),
	}
}

func (t *Topology) Close() error {
	if t != nil && t.observer != nil {
		return t.observer.Close()
	}

	return nil
}

func (t *Topology) Connect(ctx context.Context) error {
	return t.observer.Connect(ctx)
}

func (t *Topology) Containers(ctx context.Context) ([]*types.Container, error) {
	return t.observer.Containers(ctx)
}

func (t *Topology) Run(ctx context.Context, cb OnEventCallback) {
	ch := make(chan *ObservationEvent)
	go t.observer.Run(ctx, ch)

	for {
		select {
		case ev := <-ch:
			t.Lock()
			t.processEvent(ctx, ev, cb)
			t.Unlock()
		case <-ctx.Done():
			return
		}
	}
}

func (t *Topology) LookupContainer(ctx context.Context, pidns int) (*types.Container, error) {
	t.RLock()
	defer t.RUnlock()

	if container, ok := t.cache[pidns]; ok {
		ret := container.Copy()
		return ret, nil
	}

	return nil, ErrContainerNotFound
}

func (t *Topology) processEvent(ctx context.Context, ev *ObservationEvent, cb OnEventCallback) error {
	if ev == nil {
		return ErrNilEvent
	}

	container := ev.Container
	if container == nil {
		return ErrNilContainer
	}

	if container.PidNamespace <= 0 {
		return ErrBadNamespace
	}

	switch ev.Type {
	case EventTypeStart:
		t.cache[container.PidNamespace] = container
		if cb != nil {
			t.Unlock()
			cb(EventTypeStart, container)
			t.Lock()
		}
	case EventTypeStop:
		delete(t.cache, container.PidNamespace)
		if cb != nil {
			t.Unlock()
			cb(EventTypeStop, container)
			t.Lock()
		}
	default:
		return ErrUnknownType
	}

	return nil
}
