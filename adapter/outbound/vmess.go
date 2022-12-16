package outbound

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/gun"
	"github.com/Dreamacro/clash/transport/socks5"
	"github.com/Dreamacro/clash/transport/vmess"

	singVmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/packetaddr"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/net/http2"
)

var ErrUDPRemoteAddrMismatch = errors.New("udp packet dropped due to mismatched remote address")

type Vmess struct {
	*Base
	//client *vmess.Client
	client *singVmess.Client
	option *VmessOption

	// for gun mux
	gunTLSConfig *tls.Config
	gunConfig    *gun.Config
	transport    *http2.Transport
}

type VmessOption struct {
	BasicOption
	Name           string       `proxy:"name"`
	Server         string       `proxy:"server"`
	Port           int          `proxy:"port"`
	UUID           string       `proxy:"uuid"`
	AlterID        int          `proxy:"alterId"`
	Cipher         string       `proxy:"cipher"`
	UDP            bool         `proxy:"udp,omitempty"`
	Network        string       `proxy:"network,omitempty"`
	TLS            bool         `proxy:"tls,omitempty"`
	SkipCertVerify bool         `proxy:"skip-cert-verify,omitempty"`
	ServerName     string       `proxy:"servername,omitempty"`
	HTTPOpts       HTTPOptions  `proxy:"http-opts,omitempty"`
	HTTP2Opts      HTTP2Options `proxy:"h2-opts,omitempty"`
	GrpcOpts       GrpcOptions  `proxy:"grpc-opts,omitempty"`
	WSOpts         WSOptions    `proxy:"ws-opts,omitempty"`

	// add back for compatible
	WSHeaders map[string]string `proxy:"ws-headers,omitempty"`
	WSPath    string            `proxy:"ws-path,omitempty"`

	PacketAddr          bool   `proxy:"packet-addr,omitempty"`
	XUDP                bool   `proxy:"xudp,omitempty"`
	PacketEncoding      string `proxy:"packet_encoding,omitempty"`
	AuthenticatedLength bool   `proxy:"authenticated-length,omitempty"`
}

type HTTPOptions struct {
	Method  string              `proxy:"method,omitempty"`
	Path    []string            `proxy:"path,omitempty"`
	Headers map[string][]string `proxy:"headers,omitempty"`
}

type HTTP2Options struct {
	Host []string `proxy:"host,omitempty"`
	Path string   `proxy:"path,omitempty"`
}

type GrpcOptions struct {
	GrpcServiceName string `proxy:"grpc-service-name,omitempty"`
}

type WSOptions struct {
	Path                string            `proxy:"path,omitempty"`
	Headers             map[string]string `proxy:"headers,omitempty"`
	MaxEarlyData        int               `proxy:"max-early-data,omitempty"`
	EarlyDataHeaderName string            `proxy:"early-data-header-name,omitempty"`
}

// StreamConn implements C.ProxyAdapter
func (v *Vmess) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	var err error
	switch v.option.Network {
	case "ws":
		if v.option.WSOpts.Path == "" {
			v.option.WSOpts.Path = v.option.WSPath
		}
		if len(v.option.WSOpts.Headers) == 0 {
			v.option.WSOpts.Headers = v.option.WSHeaders
		}

		host, port, _ := net.SplitHostPort(v.addr)
		wsOpts := &vmess.WebsocketConfig{
			Host:                host,
			Port:                port,
			Path:                v.option.WSOpts.Path,
			MaxEarlyData:        v.option.WSOpts.MaxEarlyData,
			EarlyDataHeaderName: v.option.WSOpts.EarlyDataHeaderName,
		}

		if len(v.option.WSOpts.Headers) != 0 {
			header := http.Header{}
			for key, value := range v.option.WSOpts.Headers {
				header.Add(key, value)
			}
			wsOpts.Headers = header
		}

		if v.option.TLS {
			wsOpts.TLS = true
			wsOpts.TLSConfig = &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: v.option.SkipCertVerify,
				NextProtos:         []string{"http/1.1"},
			}
			if v.option.ServerName != "" {
				wsOpts.TLSConfig.ServerName = v.option.ServerName
			} else if host := wsOpts.Headers.Get("Host"); host != "" {
				wsOpts.TLSConfig.ServerName = host
			}
		}
		c, err = vmess.StreamWebsocketConn(c, wsOpts)
	case "http":
		// readability first, so just copy default TLS logic
		if v.option.TLS {
			host, _, _ := net.SplitHostPort(v.addr)
			tlsOpts := &vmess.TLSConfig{
				Host:           host,
				SkipCertVerify: v.option.SkipCertVerify,
			}

			if v.option.ServerName != "" {
				tlsOpts.Host = v.option.ServerName
			}

			c, err = vmess.StreamTLSConn(c, tlsOpts)
			if err != nil {
				return nil, err
			}
		}

		host, _, _ := net.SplitHostPort(v.addr)
		httpOpts := &vmess.HTTPConfig{
			Host:    host,
			Method:  v.option.HTTPOpts.Method,
			Path:    v.option.HTTPOpts.Path,
			Headers: v.option.HTTPOpts.Headers,
		}

		c = vmess.StreamHTTPConn(c, httpOpts)
	case "h2":
		host, _, _ := net.SplitHostPort(v.addr)
		tlsOpts := vmess.TLSConfig{
			Host:           host,
			SkipCertVerify: v.option.SkipCertVerify,
			NextProtos:     []string{"h2"},
		}

		if v.option.ServerName != "" {
			tlsOpts.Host = v.option.ServerName
		}

		c, err = vmess.StreamTLSConn(c, &tlsOpts)
		if err != nil {
			return nil, err
		}

		h2Opts := &vmess.H2Config{
			Hosts: v.option.HTTP2Opts.Host,
			Path:  v.option.HTTP2Opts.Path,
		}

		c, err = vmess.StreamH2Conn(c, h2Opts)
	case "grpc":
		c, err = gun.StreamGunWithConn(c, v.gunTLSConfig, v.gunConfig)
	default:
		// handle TLS
		if v.option.TLS {
			host, _, _ := net.SplitHostPort(v.addr)
			tlsOpts := &vmess.TLSConfig{
				Host:           host,
				SkipCertVerify: v.option.SkipCertVerify,
			}

			if v.option.ServerName != "" {
				tlsOpts.Host = v.option.ServerName
			}

			c, err = vmess.StreamTLSConn(c, tlsOpts)
		}
	}

	if err != nil {
		return nil, err
	}

	//return v.client.StreamConn(c, parseVmessAddr(metadata))
	if metadata.NetWork == C.UDP {
		if v.option.XUDP {
			return v.client.DialXUDPPacketConn(c, M.ParseSocksaddr(metadata.RemoteAddress()))
		} else {
			return v.client.DialPacketConn(c, M.ParseSocksaddr(metadata.RemoteAddress()))
		}
	} else {
		return v.client.DialConn(c, M.ParseSocksaddr(metadata.RemoteAddress()))
	}
}

// DialContext implements C.ProxyAdapter
func (v *Vmess) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	// gun transport
	if v.transport != nil && len(opts) == 0 {
		c, err := gun.StreamGunWithTransport(v.transport, v.gunConfig)
		if err != nil {
			return nil, err
		}
		defer func() {
			safeConnClose(c, err)
		}()

		//c, err = v.client.StreamConn(c, parseVmessAddr(metadata))
		c, err = v.client.DialConn(c, M.ParseSocksaddr(metadata.RemoteAddress()))
		if err != nil {
			return nil, err
		}

		return NewConn(c, v), nil
	}

	c, err := dialer.DialContext(ctx, "tcp", v.addr, v.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
	}
	tcpKeepAlive(c)
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = v.StreamConn(c, metadata)
	return NewConn(c, v), err
}

// ListenPacketContext implements C.ProxyAdapter
func (v *Vmess) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.PacketConn, err error) {
	// vmess use stream-oriented udp with a special address, so we needs a net.UDPAddr
	if !metadata.Resolved() {
		ip, err := resolver.ResolveIP(ctx, metadata.Host)
		if err != nil {
			return nil, errors.New("can't resolve ip")
		}
		metadata.DstIP = ip
	}

	if v.option.PacketAddr {
		_metadata := *metadata // make a copy
		metadata = &_metadata
		metadata.Host = packetaddr.SeqPacketMagicAddress
		metadata.DstPort = "443"
	}

	var c net.Conn
	// gun transport
	if v.transport != nil && len(opts) == 0 {
		c, err = gun.StreamGunWithTransport(v.transport, v.gunConfig)
		if err != nil {
			return nil, err
		}
		defer func() {
			safeConnClose(c, err)
		}()

		//c, err = v.client.StreamConn(c, parseVmessAddr(metadata))
		if v.option.XUDP {
			c, err = v.client.DialXUDPPacketConn(c, M.ParseSocksaddr(metadata.RemoteAddress()))
		} else {
			c, err = v.client.DialPacketConn(c, M.ParseSocksaddr(metadata.RemoteAddress()))
		}
	} else {
		c, err = dialer.DialContext(ctx, "tcp", v.addr, v.Base.DialOptions(opts...)...)
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
		}
		tcpKeepAlive(c)
		defer func() {
			safeConnClose(c, err)
		}()

		c, err = v.StreamConn(c, metadata)
	}

	if err != nil {
		return nil, fmt.Errorf("new vmess client error: %v", err)
	}

	return v.ListenPacketOnStreamConn(c, metadata)
}

// ListenPacketOnStreamConn implements C.ProxyAdapter
func (v *Vmess) ListenPacketOnStreamConn(c net.Conn, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if v.option.PacketAddr {
		return newPacketConn(&threadSafePacketConn{PacketConn: packetaddr.NewBindConn(c)}, v), nil
	} else if pc, ok := c.(net.PacketConn); ok {
		return newPacketConn(&threadSafePacketConn{PacketConn: pc}, v), nil
	}
	return newPacketConn(&vmessPacketConn{Conn: c, rAddr: metadata.UDPAddr()}, v), nil
}

// SupportUOT implements C.ProxyAdapter
func (v *Vmess) SupportUOT() bool {
	return true
}

func NewVmess(option VmessOption) (*Vmess, error) {
	security := strings.ToLower(option.Cipher)
	//client, err := vmess.NewClient(vmess.Config{
	//	UUID:     option.UUID,
	//	AlterID:  uint16(option.AlterID),
	//	Security: security,
	//	HostName: option.Server,
	//	Port:     strconv.Itoa(option.Port),
	//	IsAead:   option.AlterID == 0,
	//})
	var options []singVmess.ClientOption
	if option.AuthenticatedLength {
		options = append(options, singVmess.ClientWithAuthenticatedLength())
	}
	client, err := singVmess.NewClient(option.UUID, security, option.AlterID, options...)

	if err != nil {
		return nil, err
	}

	switch option.PacketEncoding {
	case "packetaddr":
		option.PacketAddr = true
	case "xudp":
		option.XUDP = true
	}
	if option.XUDP {
		option.PacketAddr = false
	}

	switch option.Network {
	case "h2", "grpc":
		if !option.TLS {
			return nil, fmt.Errorf("TLS must be true with h2/grpc network")
		}
	}

	v := &Vmess{
		Base: &Base{
			name:  option.Name,
			addr:  net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:    C.Vmess,
			udp:   option.UDP,
			iface: option.Interface,
			rmark: option.RoutingMark,
		},
		client: client,
		option: &option,
	}

	switch option.Network {
	case "h2":
		if len(option.HTTP2Opts.Host) == 0 {
			option.HTTP2Opts.Host = append(option.HTTP2Opts.Host, "www.example.com")
		}
	case "grpc":
		dialFn := func(network, addr string) (net.Conn, error) {
			c, err := dialer.DialContext(context.Background(), "tcp", v.addr, v.Base.DialOptions()...)
			if err != nil {
				return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
			}
			tcpKeepAlive(c)
			return c, nil
		}

		gunConfig := &gun.Config{
			ServiceName: v.option.GrpcOpts.GrpcServiceName,
			Host:        v.option.ServerName,
		}
		tlsConfig := &tls.Config{
			InsecureSkipVerify: v.option.SkipCertVerify,
			ServerName:         v.option.ServerName,
		}

		if v.option.ServerName == "" {
			host, _, _ := net.SplitHostPort(v.addr)
			tlsConfig.ServerName = host
			gunConfig.Host = host
		}

		v.gunTLSConfig = tlsConfig
		v.gunConfig = gunConfig
		v.transport = gun.NewHTTP2Client(dialFn, tlsConfig)
	}

	return v, nil
}

func parseVmessAddr(metadata *C.Metadata) *vmess.DstAddr {
	var addrType byte
	var addr []byte
	switch metadata.AddrType() {
	case socks5.AtypIPv4:
		addrType = byte(vmess.AtypIPv4)
		addr = metadata.DstIP.AsSlice()
	case socks5.AtypIPv6:
		addrType = byte(vmess.AtypIPv6)
		addr = metadata.DstIP.AsSlice()
	case socks5.AtypDomainName:
		addrType = byte(vmess.AtypDomainName)
		addr = make([]byte, len(metadata.Host)+1)
		addr[0] = byte(len(metadata.Host))
		copy(addr[1:], []byte(metadata.Host))
	}

	port, _ := strconv.ParseUint(metadata.DstPort, 10, 16)
	return &vmess.DstAddr{
		UDP:      metadata.NetWork == C.UDP,
		AddrType: addrType,
		Addr:     addr,
		Port:     uint(port),
	}
}

type threadSafePacketConn struct {
	net.PacketConn
	access sync.Mutex
}

func (c *threadSafePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.access.Lock()
	defer c.access.Unlock()
	return c.PacketConn.WriteTo(b, addr)
}

type vmessPacketConn struct {
	net.Conn
	rAddr  net.Addr
	access sync.Mutex
}

// WriteTo implments C.PacketConn.WriteTo
// Since VMess doesn't support full cone NAT by design, we verify if addr matches uc.rAddr, and drop the packet if not.
func (uc *vmessPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	allowedAddr := uc.rAddr.(*net.UDPAddr)
	destAddr := addr.(*net.UDPAddr)
	if !(allowedAddr.IP.Equal(destAddr.IP) && allowedAddr.Port == destAddr.Port) {
		return 0, ErrUDPRemoteAddrMismatch
	}
	uc.access.Lock()
	defer uc.access.Unlock()
	return uc.Conn.Write(b)
}

func (uc *vmessPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := uc.Conn.Read(b)
	return n, uc.rAddr, err
}
