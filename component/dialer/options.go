package dialer

import (
	"context"
	"net"

	"go.uber.org/atomic"
)

var (
	DefaultOptions     []Option
	DefaultInterface   = atomic.NewString("")
	GeneralInterface   = atomic.NewString("")
	DefaultRoutingMark = atomic.NewInt32(0)
)

type NetDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type option struct {
	interfaceName string
	addrReuse     bool
	routingMark   int
	tfo           bool
	netDialer     NetDialer
}

type Option func(opt *option)

func WithInterface(name string) Option {
	return func(opt *option) {
		opt.interfaceName = name
	}
}

func WithAddrReuse(reuse bool) Option {
	return func(opt *option) {
		opt.addrReuse = reuse
	}
}

func WithRoutingMark(mark int) Option {
	return func(opt *option) {
		opt.routingMark = mark
	}
}

func WithTFO(tfo bool) Option {
	return func(opt *option) {
		opt.tfo = tfo
	}
}

func WithNetDialer(netDialer NetDialer) Option {
	return func(opt *option) {
		opt.netDialer = netDialer
	}
}

func WithOption(o option) Option {
	return func(opt *option) {
		*opt = o
	}
}
