package event

import (
	"github.com/criticalstack/swoll/pkg/types"
	"github.com/go-redis/redis"
)

// KernelEvent is a raw event from the kernel, used by kernel event reader
type KernelEvent []byte

// KernelLostEvent is a raw lost event counter from the kernel, used by kernel event reader
type KernelLostEvent uint64

// ContainerAddEvent is an event sourced from the Topology api on
// container-entry
type ContainerAddEvent struct{ *types.Container }

// ContainerDelEvent is an event sourced from the Topology api upon
// container-exit
type ContainerDelEvent struct{ *types.Container }

// RedisEvent is an event containing a message from a redis query
type RedisEvent *redis.Message
