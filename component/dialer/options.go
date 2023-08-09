package dialer

import (
	"context"
	"net"

	"github.com/Dreamacro/clash/common/atomic"
	"github.com/Dreamacro/clash/component/resolver"
)

var (
	DefaultOptions     []Option
	DefaultInterface   = atomic.NewTypedValue[string]("")
	GeneralInterface   = atomic.NewTypedValue[string]("")
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
	mpTcp         bool
	resolver      resolver.Resolver
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

func WithResolver(r resolver.Resolver) Option {
	return func(opt *option) {
		opt.resolver = r
	}
}

func WithTFO(tfo bool) Option {
	return func(opt *option) {
		opt.tfo = tfo
	}
}

func WithMPTCP(mpTcp bool) Option {
	return func(opt *option) {
		opt.mpTcp = mpTcp
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
