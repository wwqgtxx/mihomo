package observable

import (
	"sync"

	"github.com/Dreamacro/clash/common/channel"
)

type Subscription <-chan interface{}

type Subscriber struct {
	buffer *channel.InfiniteChannel
	once   sync.Once
}

func (s *Subscriber) Emit(item interface{}) {
	s.buffer.In().(chan interface{}) <- item
}

func (s *Subscriber) Out() Subscription {
	return s.buffer.Out().(chan interface{})
}

func (s *Subscriber) Close() {
	s.once.Do(func() {
		s.buffer.Close()
	})
}

func newSubscriber() *Subscriber {
	sub := &Subscriber{
		buffer: channel.NewInfiniteChannel(make(chan interface{})),
	}
	return sub
}
