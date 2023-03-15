package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"net"

	N "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/common/utils"
	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
)

type Base struct {
	name  string
	addr  string
	iface string
	tp    C.AdapterType
	udp   bool
	tfo   bool
	rmark int
}

// Name implements C.ProxyAdapter
func (b *Base) Name() string {
	return b.name
}

// Type implements C.ProxyAdapter
func (b *Base) Type() C.AdapterType {
	return b.tp
}

// StreamConn implements C.ProxyAdapter
func (b *Base) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	return c, errors.New("no support")
}

// DialContextWithDialer implements C.ProxyAdapter
func (b *Base) DialContextWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (_ C.Conn, err error) {
	return nil, errors.New("no support")
}

// ListenPacketContext implements C.ProxyAdapter
func (b *Base) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	return nil, errors.New("no support")
}

// ListenPacketWithDialer implements C.ProxyAdapter
func (b *Base) ListenPacketWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (_ C.PacketConn, err error) {
	return nil, errors.New("no support")
}

// SupportWithDialer implements C.ProxyAdapter
func (b *Base) SupportWithDialer() bool {
	return false
}

// SupportUOT implements C.ProxyAdapter
func (b *Base) SupportUOT() bool {
	return false
}

// SupportUDP implements C.ProxyAdapter
func (b *Base) SupportUDP() bool {
	return b.udp
}

// SupportTFO implements C.ProxyAdapter
func (b *Base) SupportTFO() bool {
	return b.tfo
}

// MarshalJSON implements C.ProxyAdapter
func (b *Base) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"type": b.Type().String(),
	})
}

// Addr implements C.ProxyAdapter
func (b *Base) Addr() string {
	return b.addr
}

// Unwrap implements C.ProxyAdapter
func (b *Base) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	return nil
}

// DialOptions return []dialer.Option from struct
func (b *Base) DialOptions(opts ...dialer.Option) []dialer.Option {
	if b.iface != "" {
		opts = append(opts, dialer.WithInterface(b.iface))
	}

	if b.rmark != 0 {
		opts = append(opts, dialer.WithRoutingMark(b.rmark))
	}

	if b.tfo {
		opts = append(opts, dialer.WithTFO(true))
	}

	return opts
}

type BasicOption struct {
	TFO         bool   `proxy:"tfo,omitempty" group:"tfo,omitempty"`
	Interface   string `proxy:"interface-name,omitempty" group:"interface-name,omitempty"`
	RoutingMark int    `proxy:"routing-mark,omitempty" group:"routing-mark,omitempty"`
}

type BaseOption struct {
	Name        string
	Addr        string
	Type        C.AdapterType
	UDP         bool
	Interface   string
	RoutingMark int
}

func NewBase(opt BaseOption) *Base {
	return &Base{
		name:  opt.Name,
		addr:  opt.Addr,
		tp:    opt.Type,
		udp:   opt.UDP,
		iface: opt.Interface,
		rmark: opt.RoutingMark,
	}
}

type conn struct {
	net.Conn
	chain C.Chain
}

// Chains implements C.Connection
func (c *conn) Chains() C.Chain {
	return c.chain
}

// AppendToChains implements C.Connection
func (c *conn) AppendToChains(a C.ProxyAdapter) {
	c.chain = append(c.chain, a.Name())
}

func (c *conn) Upstream() any {
	return c.Conn
}

func NewConn(c net.Conn, a C.ProxyAdapter) C.Conn {
	return &conn{c, []string{a.Name()}}
}

type packetConn struct {
	net.PacketConn
	chain       C.Chain
	adapterName string
	connID      string
}

// Chains implements C.Connection
func (c *packetConn) Chains() C.Chain {
	return c.chain
}

// AppendToChains implements C.Connection
func (c *packetConn) AppendToChains(a C.ProxyAdapter) {
	c.chain = append(c.chain, a.Name())
}

func (c *packetConn) LocalAddr() net.Addr {
	lAddr := c.PacketConn.LocalAddr()
	return N.NewCustomAddr(c.adapterName, c.connID, lAddr) // make quic-go's connMultiplexer happy
}

func newPacketConn(pc net.PacketConn, a C.ProxyAdapter) C.PacketConn {
	return &packetConn{pc, []string{a.Name()}, a.Name(), utils.NewUUIDV4().String()}
}
