package channel

import (
	"reflect"

	"github.com/Dreamacro/clash/common/ring_queue"
)

// InfiniteChannel implements the Channel interface with an infinite buffer between the input and the output.
type InfiniteChannel struct {
	rvIn, rvOut reflect.Value
	in, out     interface{}
	length      chan int
	rvLength    reflect.Value
	buffer      *ring_queue.Queue
}

func NewInfiniteChannel(chanExample interface{}) *InfiniteChannel {
	if chanExample == nil {
		chanExample = new(chan interface{})
	}

	rv := reflect.ValueOf(chanExample)
	if rk := rv.Kind(); rk != reflect.Chan {
		panic("expecting type: 'chan ...'  instead got: " + rk.String())
	}

	ch := &InfiniteChannel{}
	ch.rvIn = reflect.MakeChan(rv.Type(), 0)
	ch.rvOut = reflect.MakeChan(rv.Type(), 0)
	ch.in = ch.rvIn.Interface()
	ch.out = ch.rvOut.Interface()
	ch.length = make(chan int)
	ch.rvLength = reflect.ValueOf(ch.length)
	ch.buffer = ring_queue.New()

	go ch.infiniteBuffer()

	return ch
}

func (ch *InfiniteChannel) In() interface{} {
	return ch.in
}

func (ch *InfiniteChannel) Out() interface{} {
	return ch.out
}

func (ch *InfiniteChannel) Len() int {
	return <-ch.length
}

func (ch *InfiniteChannel) Close() {
	ch.rvIn.Close()
}

func (ch *InfiniteChannel) infiniteBuffer() {
	var input, output reflect.Value
	var next interface{}

	input = ch.rvIn

	selectCase := make([]reflect.SelectCase, 3)

	for input.IsValid() || output.IsValid() {
		selectCase[0].Dir = reflect.SelectRecv
		selectCase[0].Chan = input
		selectCase[1].Dir = reflect.SelectSend
		selectCase[1].Chan = output
		selectCase[1].Send = reflect.ValueOf(next)
		selectCase[2].Dir = reflect.SelectSend
		selectCase[2].Chan = ch.rvLength
		selectCase[2].Send = reflect.ValueOf(ch.buffer.Length())

		chosen, recv, recvOk := reflect.Select(selectCase)
		switch chosen {
		case 0:
			if recvOk {
				ch.buffer.Add(recv.Interface())
			} else {
				input = reflect.Value{}
			}
		case 1:
			ch.buffer.Remove()
		case 2:
		}

		if ch.buffer.Length() > 0 {
			output = ch.rvOut
			next = ch.buffer.Peek()
		} else {
			output = reflect.Value{}
			next = nil
		}
	}

	ch.rvOut.Close()
	ch.rvLength.Close()
}
