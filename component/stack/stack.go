package stack

import (
	"sync"
)

type (
	Stack struct {
		top    *node
		length int
		lock   *sync.RWMutex
	}
	node struct {
		value interface{}
		prev  *node
	}
)

// NewStack Create a new stack
func NewStack() *Stack {
	return &Stack{nil, 0, &sync.RWMutex{}}
}

// Len Return the number of items in the stack
func (stack *Stack) Len() int {
	return stack.length
}

// Peek View the top item on the stack
func (stack *Stack) Peek() interface{} {
	if stack.length == 0 {
		return nil
	}
	return stack.top.value
}

// Pop the top item of the stack and return it
func (stack *Stack) Pop() interface{} {
	stack.lock.Lock()
	defer stack.lock.Unlock()
	if stack.length == 0 {
		return nil
	}
	n := stack.top
	stack.top = n.prev
	stack.length--
	return n.value
}

// Push a value onto the top of the stack
func (stack *Stack) Push(value interface{}) {
	stack.lock.Lock()
	defer stack.lock.Unlock()
	n := &node{value, stack.top}
	stack.top = n
	stack.length++
}
