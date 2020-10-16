package topology

import (
	"context"

	"github.com/criticalstack/swoll/pkg/types"
)

type Runtime interface {
	Containers(ctx context.Context, procroot string) ([]*types.Container, error)
	Connect(ctx context.Context) error
	Close() error
}
