package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"

	D "github.com/miekg/dns"
	"github.com/zhangyunhao116/fastrand"
)

const (
	// dotMimeType is the DoH mimetype that should be used.
	dotMimeType = "application/dns-message"
)

type dohClient struct {
	url       string
	transport *http.Transport
}

var _ dnsClient = (*dohClient)(nil)

// Address implements dnsClient
func (dc *dohClient) Address() string {
	return dc.url
}

func (dc *dohClient) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	// https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
	// In order to maximize cache friendliness, SHOULD use a DNS ID of 0 in every DNS request.
	newM := *m
	newM.Id = 0
	req, err := dc.newRequest(&newM)
	if err != nil {
		return nil, err
	}

	req = req.WithContext(ctx)
	msg, err = dc.doRequest(req)
	if err == nil {
		msg.Id = m.Id
	}
	return
}

// newRequest returns a new DoH request given a dns.Msg.
func (dc *dohClient) newRequest(m *D.Msg) (*http.Request, error) {
	buf, err := m.Pack()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, dc.url, bytes.NewReader(buf))
	if err != nil {
		return req, err
	}

	req.Header.Set("content-type", dotMimeType)
	req.Header.Set("accept", dotMimeType)
	return req, nil
}

func (dc *dohClient) doRequest(req *http.Request) (msg *D.Msg, err error) {
	client := &http.Client{Transport: dc.transport, Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	msg = &D.Msg{}
	err = msg.Unpack(buf)
	return msg, err
}

func newDoHClient(url, iface string, r *Resolver, useRemote bool, proxyAdapter C.ProxyAdapter, proxyName string) *dohClient {
	return &dohClient{
		url: url,
		transport: &http.Transport{
			ForceAttemptHTTP2: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if useRemote || proxyName != "" {
					return remoteDialer.DialTCP(addr, proxyName)
				}

				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				uintPort, err := strconv.ParseUint(port, 10, 16)
				if err != nil {
					return nil, err
				}

				ips, err := resolver.LookupIPWithResolver(ctx, host, r)
				if err != nil {
					return nil, err
				} else if len(ips) == 0 {
					return nil, fmt.Errorf("%w: %s", resolver.ErrIPNotFound, host)
				}
				ip := ips[fastrand.Intn(len(ips))]

				options := []dialer.Option{}
				if iface != "" {
					options = append(options, dialer.WithInterface(iface))
				}

				if proxyAdapter != nil {
					metadata := &C.Metadata{
						Type:    C.DNS,
						NetWork: C.TCP,
						DstIP:   ip,
						DstPort: uint16(uintPort),
					}
					return proxyAdapter.DialContext(ctx, metadata)
				}

				return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port), options...)
			},
			TLSClientConfig: ca.GetGlobalTLSConfig(&tls.Config{
				// alpn identifier, see https://tools.ietf.org/html/draft-hoffman-dprive-dns-tls-alpn-00#page-6
				NextProtos: []string{"dns"},
			}),
		},
	}
}
