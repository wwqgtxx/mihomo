package observable

import (
	"sync"

	"github.com/Dreamacro/clash/common/channel"
)

type Subscription <-chan interface{}

type Subscriber struct {
	buffer *channel.InfiniteChannel[interface{}]
	once   sync.Once
}

func (s *Subscriber) Emit(item interface{}) {
	s.buffer.In() <- item
}

func (s *Subscriber) Out() Subscription {
	return s.buffer.Out()
}

func (s *Subscriber) Close() {
	s.once.Do(func() {
		s.buffer.Close()
	})
}

func newSubscriber() *Subscriber {
	sub := &Subscriber{
		buffer: channel.NewInfiniteChannel[interface{}](),
	}
	return sub
}
