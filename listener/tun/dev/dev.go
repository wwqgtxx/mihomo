package dev

import "gvisor.dev/gvisor/pkg/tcpip/stack"

// TunDevice is cross-platform tun interface
type TunDevice interface {
	Name() string
	URL() string
	AsLinkEndpoint() (stack.LinkEndpoint, error)
	Close()
}
