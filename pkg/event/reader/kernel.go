package reader

import (
	"context"
	"errors"

	"github.com/criticalstack/swoll/pkg/event"
	"github.com/criticalstack/swoll/pkg/kernel"
)

// KernelReader handles callbacks from the kernel and implements a higher level
// channel-based emission to clients
type KernelReader struct {
	probe   *kernel.Probe
	backlog chan interface{}
}

// NewKernelReader creates a kernel event reader from a `kernel.Probe` context
func NewKernelReader(probe *kernel.Probe) EventReader {
	return &KernelReader{probe, make(chan interface{})}
}

// Read returns the channel of processed events.
func (k *KernelReader) Read() chan interface{} {
	return k.backlog
}

// handler converts the raw bytes into a KernelEvent and
// writes it to the backlog. We assume here that if msg is nil,
// that this is a lost msg and emit it as so.
func (k *KernelReader) handler(msg []byte, lost uint64) error {
	if msg != nil {
		k.backlog <- event.KernelEvent(msg)
	}
	return nil
}

// Run starts up the kernel reader in its own goroutine,
// then simply reads the raw messages in, and pipes them
// to the KernelEvent channel.
func (k *KernelReader) Run(ctx context.Context) error {
	if k == nil {
		return errors.New("nil context")
	}

	//nolint:errcheck
	go k.probe.Run(ctx, k.handler)
	<-ctx.Done()

	return nil
}
