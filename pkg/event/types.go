package event

import (
	"github.com/criticalstack/swoll/pkg/podmon"
	"github.com/go-redis/redis"
)

// KernelEvent is a raw event from the kernel, used by kernel event reader
type KernelEvent []byte

// KernelLostEvent is a raw lost event counter from the kernel, used by kernel event reader
type KernelLostEvent uint64

// PodmonAddEvent is an event containing information about a container that was
// added to the k8s cluster.
type PodmonAddEvent struct{ *podmon.CRIContainer }

// PodmonDelEvent is an event containing information about a container that was
// deleted from the k8s cluster.
type PodmonDelEvent struct{ *podmon.CRIContainer }

// RedisEvent is an event containing a message from a redis query
type RedisEvent *redis.Message
