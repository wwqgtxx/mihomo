package observable

import (
	"sync"

	"github.com/Dreamacro/clash/common/channel"
)

type Subscription <-chan any

type Subscriber struct {
	buffer *channel.InfiniteChannel[any]
	once   sync.Once
}

func (s *Subscriber) Emit(item any) {
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
		buffer: channel.NewInfiniteChannel[any](),
	}
	return sub
}
