package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/resolver"

	D "github.com/miekg/dns"
)

type client struct {
	*D.Client
	r         *Resolver
	port      string
	host      string
	useRemote bool
}

func (c *client) UseRemote() bool {
	return c.useRemote
}

func (c *client) Exchange(m *D.Msg) (msg *D.Msg, err error) {
	return c.ExchangeContext(context.Background(), m)
}

func (c *client) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	var ip net.IP
	if c.r == nil {
		// a default ip dns
		ip = net.ParseIP(c.host)
	} else {
		if ip, err = resolver.ResolveIPWithResolver(c.host, c.r); err != nil {
			return nil, fmt.Errorf("use default dns resolve failed: %w", err)
		}
	}

	d, err := dialer.Dialer()
	if err != nil {
		return nil, err
	}

	if ip != nil && ip.IsGlobalUnicast() && dialer.DialHook != nil {
		network := "udp"
		if strings.HasPrefix(c.Client.Net, "tcp") {
			network = "tcp"
		}
		if err := dialer.DialHook(d, network, ip); err != nil {
			return nil, err
		}
	}

	c.Client.Dialer = d

	// miekg/dns ExchangeContext doesn't respond to context cancel.
	// this is a workaround
	type result struct {
		msg *D.Msg
		err error
	}
	ch := make(chan result, 1)
	go func() {
		if c.useRemote {
			conn, err := c.remoteDial(net.JoinHostPort(ip.String(), c.port))
			if err != nil {
				ch <- result{msg, err}
			}
			msg, _, err := c.Client.ExchangeWithConn(m, conn)
			ch <- result{msg, err}
			return
		}

		msg, _, err := c.Client.Exchange(m, net.JoinHostPort(ip.String(), c.port))
		ch <- result{msg, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ret := <-ch:
		return ret.msg, ret.err
	}
}

func (c *client) remoteDial(address string) (conn *D.Conn, err error) {
	network := c.Net
	if network == "" || network == "udp" { // force use tcp when do remote dns
		network = "tcp"
	}

	useTLS := strings.HasPrefix(network, "tcp") && strings.HasSuffix(network, "-tls")
	network = strings.TrimSuffix(network, "-tls")

	conn = new(D.Conn)

	conn.Conn, err = remoteDial(network, address)
	if useTLS {
		tlsConn := tls.Client(conn.Conn, c.TLSConfig)
		err = tlsConn.Handshake()
		conn.Conn = tlsConn
	}
	if err != nil {
		return nil, err
	}
	conn.UDPSize = c.UDPSize
	return conn, nil
}
