package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"
)

const (
	// dotMimeType is the DoH mimetype that should be used.
	dotMimeType = "application/dns-message"
)

type dohClient struct {
	url         string
	transport   *http.Transport
	ecsPrefix   netip.Prefix
	ecsOverride bool
}

var _ dnsClient = (*dohClient)(nil)

// Address implements dnsClient
func (doh *dohClient) Address() string {
	return doh.url
}

func (doh *dohClient) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	// https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
	// In order to maximize cache friendliness, SHOULD use a DNS ID of 0 in every DNS request.
	newM := m.Copy()
	newM.Id = 0

	if doh.ecsPrefix.IsValid() {
		setEdns0Subnet(m, doh.ecsPrefix, doh.ecsOverride)
	}

	req, err := doh.newRequest(newM)
	if err != nil {
		return nil, err
	}

	req = req.WithContext(ctx)
	msg, err = doh.doRequest(req)
	if err == nil {
		msg.Id = m.Id
	}
	return
}

// newRequest returns a new DoH request given a dns.Msg.
func (doh *dohClient) newRequest(m *D.Msg) (*http.Request, error) {
	buf, err := m.Pack()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, doh.url, bytes.NewReader(buf))
	if err != nil {
		return req, err
	}

	req.Header.Set("content-type", dotMimeType)
	req.Header.Set("accept", dotMimeType)
	return req, nil
}

func (doh *dohClient) doRequest(req *http.Request) (msg *D.Msg, err error) {
	client := &http.Client{Transport: doh.transport, Timeout: 5 * time.Second}
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

func newDoHClient(url string, r *Resolver, proxyAdapter C.ProxyAdapter, proxyName string, params map[string]string) *dohClient {
	tlsConfig := &tls.Config{
		// alpn identifier, see https://tools.ietf.org/html/draft-hoffman-dprive-dns-tls-alpn-00#page-6
		NextProtos: []string{"dns"},
	}
	if params["skip-cert-verify"] == "true" {
		tlsConfig.InsecureSkipVerify = true
	}
	doh := &dohClient{
		url: url,
		transport: &http.Transport{
			ForceAttemptHTTP2: true,
			DialContext:       newDNSDialer(r, proxyAdapter, proxyName).DialContext,
			TLSClientConfig:   ca.GetGlobalTLSConfig(tlsConfig),
		},
	}

	if ecs := params["ecs"]; ecs != "" {
		prefix, err := netip.ParsePrefix(ecs)
		if err != nil {
			addr, err := netip.ParseAddr(ecs)
			if err != nil {
				log.Warnln("DOH [%s] config with invalid ecs: %s", url, ecs)
			} else {
				doh.ecsPrefix = netip.PrefixFrom(addr, addr.BitLen())
			}
		} else {
			doh.ecsPrefix = prefix
		}
	}

	if doh.ecsPrefix.IsValid() {
		log.Debugln("DOH [%s] config with ecs: %s", url, doh.ecsPrefix)
	}

	if params["ecs-override"] == "true" {
		doh.ecsOverride = true
	}

	return doh
}
