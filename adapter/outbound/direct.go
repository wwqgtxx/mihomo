package outbound

import (
	"context"
	"errors"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
)

type Direct struct {
	*Base
}

type DirectOption struct {
	BasicOption
	Name string `proxy:"name"`
}

// DialContext implements C.ProxyAdapter
func (d *Direct) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	opts = append(opts, dialer.WithResolver(resolver.ProxyServerHostResolver))
	c, err := dialer.DialContext(ctx, "tcp", metadata.RemoteAddress(), d.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, err
	}
	return NewConn(c, d), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (d *Direct) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	// net.UDPConn.WriteTo only working with *net.UDPAddr, so we need a net.UDPAddr
	if !metadata.Resolved() {
		ip, err := resolver.ResolveIPWithResolver(ctx, metadata.Host, resolver.ProxyServerHostResolver)
		if err != nil {
			return nil, errors.New("can't resolve ip")
		}
		metadata.DstIP = ip
	}
	pc, err := dialer.NewDialer(d.Base.DialOptions(opts...)...).ListenPacket(ctx, "udp", "", metadata.AddrPort())
	if err != nil {
		return nil, err
	}
	return newPacketConn(pc, d), nil
}

func NewDirect() *Direct {
	return &Direct{
		Base: &Base{
			name: "DIRECT",
			tp:   C.Direct,
			udp:  true,
		},
	}
}

func (d *Direct) IsL3Protocol(metadata *C.Metadata) bool {
	return true // tell DNSDialer don't send domain to DialContext, avoid lookback to DefaultResolver
}

func NewDirectWithOption(option DirectOption) *Direct {
	return &Direct{
		Base: &Base{
			name:   option.Name,
			tp:     C.Direct,
			udp:    true,
			tfo:    option.TFO,
			mpTcp:  option.MPTCP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: C.NewDNSPrefer(option.IPVersion),
		},
	}
}

func NewCompatible() *Direct {
	return &Direct{
		Base: &Base{
			name: "COMPATIBLE",
			tp:   C.Compatible,
			udp:  true,
		},
	}
}
