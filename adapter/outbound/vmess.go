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

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/gun"
	"github.com/metacubex/mihomo/transport/socks5"
	"github.com/metacubex/mihomo/transport/vmess"

	singVmess "github.com/metacubex/sing-vmess"
	"github.com/metacubex/sing-vmess/packetaddr"
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
	Fingerprint    string       `proxy:"fingerprint,omitempty"`
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
	PacketEncoding      string `proxy:"packet-encoding,omitempty"`
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
	Path                     string            `proxy:"path,omitempty"`
	Headers                  map[string]string `proxy:"headers,omitempty"`
	MaxEarlyData             int               `proxy:"max-early-data,omitempty"`
	EarlyDataHeaderName      string            `proxy:"early-data-header-name,omitempty"`
	V2rayHttpUpgrade         bool              `proxy:"v2ray-http-upgrade,omitempty"`
	V2rayHttpUpgradeFastOpen bool              `proxy:"v2ray-http-upgrade-fast-open,omitempty"`
}

// StreamConnContext implements C.ProxyAdapter
func (v *Vmess) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
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
			Host:                     host,
			Port:                     port,
			Path:                     v.option.WSOpts.Path,
			MaxEarlyData:             v.option.WSOpts.MaxEarlyData,
			EarlyDataHeaderName:      v.option.WSOpts.EarlyDataHeaderName,
			V2rayHttpUpgrade:         v.option.WSOpts.V2rayHttpUpgrade,
			V2rayHttpUpgradeFastOpen: v.option.WSOpts.V2rayHttpUpgradeFastOpen,
			Headers:                  http.Header{},
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
			tlsConfig := &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: v.option.SkipCertVerify,
				NextProtos:         []string{"http/1.1"},
			}
			wsOpts.TLSConfig, err = ca.GetSpecifiedFingerprintTLSConfig(tlsConfig, v.option.Fingerprint)
			if err != nil {
				return nil, err
			}
			if v.option.ServerName != "" {
				wsOpts.TLSConfig.ServerName = v.option.ServerName
			} else if host := wsOpts.Headers.Get("Host"); host != "" {
				wsOpts.TLSConfig.ServerName = host
			}
		}
		c, err = vmess.StreamWebsocketConn(ctx, c, wsOpts)
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

			c, err = vmess.StreamTLSConn(ctx, c, tlsOpts)
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
			FingerPrint:    v.option.Fingerprint,
			NextProtos:     []string{"h2"},
		}

		if v.option.ServerName != "" {
			tlsOpts.Host = v.option.ServerName
		}

		c, err = vmess.StreamTLSConn(ctx, c, &tlsOpts)
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
				FingerPrint:    v.option.Fingerprint,
			}

			if v.option.ServerName != "" {
				tlsOpts.Host = v.option.ServerName
			}

			c, err = vmess.StreamTLSConn(ctx, c, tlsOpts)
		}
	}

	if err != nil {
		return nil, err
	}

	//return v.client.StreamConn(c, parseVmessAddr(metadata))
	return v.streamConn(c, metadata)
}

func (v *Vmess) streamConn(c net.Conn, metadata *C.Metadata) (conn net.Conn, err error) {
	if metadata.NetWork == C.UDP {
		if v.option.XUDP {
			var globalID [8]byte
			if metadata.SourceValid() {
				globalID = utils.GlobalID(metadata.SourceAddress())
			}
			if N.NeedHandshake(c) {
				conn = v.client.DialEarlyXUDPPacketConn(c,
					globalID,
					M.SocksaddrFromNet(metadata.UDPAddr()))
			} else {
				conn, err = v.client.DialXUDPPacketConn(c,
					globalID,
					M.SocksaddrFromNet(metadata.UDPAddr()))
			}
		} else if v.option.PacketAddr {
			if N.NeedHandshake(c) {
				conn = v.client.DialEarlyPacketConn(c,
					M.ParseSocksaddrHostPort(packetaddr.SeqPacketMagicAddress, 443))
			} else {
				conn, err = v.client.DialPacketConn(c,
					M.ParseSocksaddrHostPort(packetaddr.SeqPacketMagicAddress, 443))
			}
		} else {
			if N.NeedHandshake(c) {
				conn = v.client.DialEarlyPacketConn(c,
					M.SocksaddrFromNet(metadata.UDPAddr()))
			} else {
				conn, err = v.client.DialPacketConn(c,
					M.SocksaddrFromNet(metadata.UDPAddr()))
			}
		}
	} else {
		if N.NeedHandshake(c) {
			conn = v.client.DialEarlyConn(c,
				M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
		} else {
			conn, err = v.client.DialConn(c,
				M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
		}
	}
	if err != nil {
		conn = nil
	}
	return
}

// DialContext implements C.ProxyAdapter
func (v *Vmess) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	// gun transport
	if v.transport != nil && len(opts) == 0 {
		c, err := gun.StreamGunWithTransport(v.transport, v.gunConfig)
		if err != nil {
			return nil, err
		}
		defer func(c net.Conn) {
			safeConnClose(c, err)
		}(c)

		//c, err = v.client.StreamConn(c, parseVmessAddr(metadata))
		c, err = v.client.DialConn(c, M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
		if err != nil {
			return nil, err
		}

		return NewConn(c, v), nil
	}
	return v.DialContextWithDialer(ctx, dialer.NewDialer(v.Base.DialOptions(opts...)...), metadata)
}

// DialContextWithDialer implements C.ProxyAdapter
func (v *Vmess) DialContextWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (_ C.Conn, err error) {
	if len(v.option.DialerProxy) > 0 {
		dialer, err = proxydialer.NewByName(v.option.DialerProxy, dialer)
		if err != nil {
			return nil, err
		}
	}
	c, err := dialer.DialContext(ctx, "tcp", v.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
	}
	N.TCPKeepAlive(c)
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = v.StreamConnContext(ctx, c, metadata)
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
	var c net.Conn
	// gun transport
	if v.transport != nil && len(opts) == 0 {
		c, err = gun.StreamGunWithTransport(v.transport, v.gunConfig)
		if err != nil {
			return nil, err
		}
		defer func(c net.Conn) {
			safeConnClose(c, err)
		}(c)

		//c, err = v.client.StreamConn(c, parseVmessAddr(metadata))
		c, err = v.streamConn(c, metadata)
		if err != nil {
			return nil, fmt.Errorf("new vmess client error: %v", err)
		}
		return v.ListenPacketOnStreamConn(ctx, c, metadata)
	}
	return v.ListenPacketWithDialer(ctx, dialer.NewDialer(v.Base.DialOptions(opts...)...), metadata)
}

// ListenPacketWithDialer implements C.ProxyAdapter
func (v *Vmess) ListenPacketWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if len(v.option.DialerProxy) > 0 {
		dialer, err = proxydialer.NewByName(v.option.DialerProxy, dialer)
		if err != nil {
			return nil, err
		}
	}
	// vmess use stream-oriented udp with a special address, so we needs a net.UDPAddr
	if !metadata.Resolved() {
		ip, err := resolver.ResolveIP(ctx, metadata.Host)
		if err != nil {
			return nil, errors.New("can't resolve ip")
		}
		metadata.DstIP = ip
	}

	c, err := dialer.DialContext(ctx, "tcp", v.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
	}
	N.TCPKeepAlive(c)
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = v.StreamConnContext(ctx, c, metadata)
	if err != nil {
		return nil, fmt.Errorf("new vmess client error: %v", err)
	}

	return v.ListenPacketOnStreamConn(ctx, c, metadata)
}

// ListenPacketOnStreamConn implements C.ProxyAdapter
func (v *Vmess) ListenPacketOnStreamConn(ctx context.Context, c net.Conn, metadata *C.Metadata) (_ C.PacketConn, err error) {
	// vmess use stream-oriented udp with a special address, so we need a net.UDPAddr
	if !metadata.Resolved() {
		ip, err := resolver.ResolveIP(ctx, metadata.Host)
		if err != nil {
			return nil, errors.New("can't resolve ip")
		}
		metadata.DstIP = ip
	}

	if pc, ok := c.(net.PacketConn); ok {
		return newPacketConn(N.NewThreadSafePacketConn(pc), v), nil
	}
	return newPacketConn(&vmessPacketConn{Conn: c, rAddr: metadata.UDPAddr()}, v), nil
}

// SupportWithDialer implements C.ProxyAdapter
func (v *Vmess) SupportWithDialer() C.NetWork {
	return C.ALLNet
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
			tfo:   option.TFO,
			mpTcp: option.MPTCP,
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
			var err error
			var cDialer C.Dialer = dialer.NewDialer(v.Base.DialOptions()...)
			if len(v.option.DialerProxy) > 0 {
				cDialer, err = proxydialer.NewByName(v.option.DialerProxy, cDialer)
				if err != nil {
					return nil, err
				}
			}
			c, err := cDialer.DialContext(context.Background(), "tcp", v.addr)
			if err != nil {
				return nil, fmt.Errorf("%s connect error: %s", v.addr, err.Error())
			}
			N.TCPKeepAlive(c)
			return c, nil
		}

		gunConfig := &gun.Config{
			ServiceName: v.option.GrpcOpts.GrpcServiceName,
			Host:        v.option.ServerName,
		}
		tlsConfig := ca.GetGlobalTLSConfig(&tls.Config{
			InsecureSkipVerify: v.option.SkipCertVerify,
			ServerName:         v.option.ServerName,
		})

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

	return &vmess.DstAddr{
		UDP:      metadata.NetWork == C.UDP,
		AddrType: addrType,
		Addr:     addr,
		Port:     uint(metadata.DstPort),
	}
}

type vmessPacketConn struct {
	net.Conn
	rAddr  net.Addr
	access sync.Mutex
}

// WriteTo implments C.PacketConn.WriteTo
// Since VMess doesn't support full cone NAT by design, we verify if addr matches uc.rAddr, and drop the packet if not.
func (uc *vmessPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	allowedAddr := uc.rAddr
	destAddr := addr
	if allowedAddr.String() != destAddr.String() {
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
