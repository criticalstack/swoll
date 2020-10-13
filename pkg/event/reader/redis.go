package reader

import (
	"context"

	"github.com/criticalstack/swoll/pkg/event"
	"github.com/go-redis/redis"
)

// RedisReader reads events from a redis client PubSub,
// And outputs as a event.Trace record into its backlog.
type RedisReader struct {
	pubsub  *redis.PubSub
	backlog chan interface{}
}

func NewRedisReader(pubsub *redis.PubSub) EventReader {
	return &RedisReader{
		pubsub:  pubsub,
		backlog: make(chan interface{}),
	}
}

func (r *RedisReader) Run(ctx context.Context) error {
	//ch := client.ps.Channel()

	for {
		select {
		case msg := <-r.pubsub.Channel():
			r.backlog <- event.RedisEvent(msg)
		case <-ctx.Done():
			// TODO[mark] log cancelation error here.
			return ctx.Err()
		}
	}
}

func (r RedisReader) Read() chan interface{} {
	return r.backlog
}
