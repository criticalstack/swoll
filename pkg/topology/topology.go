package topology

import (
	"context"
	"log"
	"sync"

	"github.com/criticalstack/swoll/pkg/types"
)

type Topology struct {
	sync.RWMutex
	runtime  Runtime
	watcher  Watcher
	pnscache map[int]*types.Container
}

func (t *Topology) LookupNamespace(pidns int) *types.Container {
	t.RLock()
	defer t.RUnlock()

	return t.pnscache[pidns]
}

func (t *Topology) updateCache(etype WatchEventType, container *types.Container) {

}

func (t *Topology) Run(ctx context.Context) error {
	evchan := make(chan *WatchEvent)

	go func() {
		if err := t.watcher.Run(ctx, evchan); err != nil {
			log.Fatal(err)
		}
	}()

	for {
		select {
		case ev := <-evchan:
			t.Lock()
			t.updateCache(ev.Type, ev.Container)
			t.Unlock()
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}
