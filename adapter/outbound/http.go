package outbound

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/proxydialer"
	C "github.com/Dreamacro/clash/constant"
)

type Http struct {
	*Base
	option    *HttpOption
	user      string
	pass      string
	tlsConfig *tls.Config
	Headers   http.Header
}

type HttpOption struct {
	BasicOption
	Name           string            `proxy:"name"`
	Server         string            `proxy:"server"`
	Port           int               `proxy:"port"`
	UserName       string            `proxy:"username,omitempty"`
	Password       string            `proxy:"password,omitempty"`
	TLS            bool              `proxy:"tls,omitempty"`
	SNI            string            `proxy:"sni,omitempty"`
	SkipCertVerify bool              `proxy:"skip-cert-verify,omitempty"`
	Headers        map[string]string `proxy:"headers,omitempty"`
}

// StreamConnContext implements C.ProxyAdapter
func (h *Http) StreamConnContext(ctx context.Context, c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	if h.tlsConfig != nil {
		cc := tls.Client(c, h.tlsConfig)
		err := cc.HandshakeContext(ctx)
		c = cc
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", h.addr, err)
		}
	}

	if err := h.shakeHand(metadata, c); err != nil {
		return nil, err
	}
	return c, nil
}

// DialContext implements C.ProxyAdapter
func (h *Http) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	return h.DialContextWithDialer(ctx, dialer.NewDialer(h.Base.DialOptions(opts...)...), metadata)
}

// DialContextWithDialer implements C.ProxyAdapter
func (h *Http) DialContextWithDialer(ctx context.Context, dialer C.Dialer, metadata *C.Metadata) (_ C.Conn, err error) {
	if len(h.option.DialerProxy) > 0 {
		dialer, err = proxydialer.NewByName(h.option.DialerProxy, dialer)
		if err != nil {
			return nil, err
		}
	}
	c, err := dialer.DialContext(ctx, "tcp", h.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", h.addr, err)
	}
	tcpKeepAlive(c)

	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	c, err = h.StreamConnContext(ctx, c, metadata)
	if err != nil {
		return nil, err
	}

	return NewConn(c, h), nil
}

// SupportWithDialer implements C.ProxyAdapter
func (h *Http) SupportWithDialer() C.NetWork {
	return C.TCP
}

func (h *Http) shakeHand(metadata *C.Metadata, rw io.ReadWriter) error {
	addr := metadata.RemoteAddress()
	req := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Host: addr,
		},
		Host:   addr,
		Header: h.Headers.Clone(),
	}

	req.Header.Add("Proxy-Connection", "Keep-Alive")

	if h.user != "" && h.pass != "" {
		auth := h.user + ":" + h.pass
		req.Header.Add("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	}

	if err := req.Write(rw); err != nil {
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(rw), req)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	if resp.StatusCode == http.StatusProxyAuthRequired {
		return errors.New("HTTP need auth")
	}

	if resp.StatusCode == http.StatusMethodNotAllowed {
		return errors.New("CONNECT method not allowed by proxy")
	}

	if resp.StatusCode >= http.StatusInternalServerError {
		return errors.New(resp.Status)
	}

	return fmt.Errorf("can not connect remote err code: %d", resp.StatusCode)
}

func NewHttp(option HttpOption) *Http {
	var tlsConfig *tls.Config
	if option.TLS {
		sni := option.Server
		if option.SNI != "" {
			sni = option.SNI
		}
		tlsConfig = &tls.Config{
			InsecureSkipVerify: option.SkipCertVerify,
			ServerName:         sni,
		}
	}

	headers := http.Header{}
	for name, value := range option.Headers {
		headers.Add(name, value)
	}

	return &Http{
		Base: &Base{
			name:  option.Name,
			addr:  net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:    C.Http,
			tfo:   option.TFO,
			mpTcp: option.MPTCP,
			iface: option.Interface,
			rmark: option.RoutingMark,
		},
		option:    &option,
		user:      option.UserName,
		pass:      option.Password,
		tlsConfig: tlsConfig,
		Headers:   headers,
	}
}
