package topology

import (
	"context"

	"github.com/criticalstack/swoll/pkg/types"
)

type WatchEventType int

const (
	WatchEventUp WatchEventType = iota
	WatchEventDown
)

type WatchEvent struct {
	Type      WatchEventType
	Container *types.Container
}

type Watcher interface {
	Connect(ctx context.Context) error
	Run(ctx context.Context, out chan<- *WatchEvent) error
	Close() error
}
