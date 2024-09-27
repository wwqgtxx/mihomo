package adapter

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/callback"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/queue"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	C "github.com/metacubex/mihomo/constant"
)

type Proxy struct {
	C.ProxyAdapter
	history       *queue.Queue
	alive         atomic.Bool
	ignoreURLTest bool
}

// Adapter implements C.Proxy
func (p *Proxy) Adapter() C.ProxyAdapter {
	return p.ProxyAdapter
}

// Alive implements C.Proxy
func (p *Proxy) Alive() bool {
	if proxy := p.ProxyAdapter.Unwrap(nil, false); proxy != nil {
		return proxy.Alive()
	}
	return p.alive.Load()
}

// Dial implements C.Proxy
func (p *Proxy) Dial(metadata *C.Metadata) (C.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTCPTimeout)
	defer cancel()
	return p.DialContext(ctx, metadata)
}

// DialContext implements C.ProxyAdapter
func (p *Proxy) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.Conn, error) {
	beginTime := time.Now()
	c, err := p.ProxyAdapter.DialContext(ctx, metadata, opts...)
	aliveCallback(beginTime, err, p, ctx)

	if N.NeedHandshake(c) {
		c = callback.NewFirstWriteCallBackConn(c, func(err error) {
			aliveCallback(beginTime, err, p, ctx)
		})
	}

	return c, err
}

// DialUDP implements C.ProxyAdapter
func (p *Proxy) DialUDP(metadata *C.Metadata) (C.PacketConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultUDPTimeout)
	defer cancel()
	return p.ListenPacketContext(ctx, metadata)
}

// ListenPacketContext implements C.ProxyAdapter
func (p *Proxy) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	beginTime := time.Now()
	pc, err := p.ProxyAdapter.ListenPacketContext(ctx, metadata, opts...)
	aliveCallback(beginTime, err, p, ctx)
	return pc, err
}

func aliveCallback(beginTime time.Time, err error, p *Proxy, ctx context.Context) {
	timeUsed := time.Since(beginTime)
	if err != nil {
		if ctx.Err() == nil || timeUsed > 1*time.Second { // context not cancelled or timeUsed>1s
			p.alive.Store(false)
		}
	}
}

// DelayHistory implements C.Proxy
func (p *Proxy) DelayHistory() []C.DelayHistory {
	if proxy := p.ProxyAdapter.Unwrap(nil, false); proxy != nil {
		return proxy.DelayHistory()
	}
	queue := p.history.Copy()
	histories := []C.DelayHistory{}
	for _, item := range queue {
		histories = append(histories, item.(C.DelayHistory))
	}
	return histories
}

// LastDelay return last history record. if proxy is not alive, return the max value of uint16.
// implements C.Proxy
func (p *Proxy) LastDelay() (delay uint16) {
	if proxy := p.ProxyAdapter.Unwrap(nil, false); proxy != nil {
		return proxy.LastDelay()
	}
	var max uint16 = 0xffff
	if !p.alive.Load() {
		return max
	}

	last := p.history.Last()
	if last == nil {
		return max
	}
	history := last.(C.DelayHistory)
	if history.Delay == 0 {
		return max
	}
	return history.Delay
}

// LastMeanDelay return last history record. if proxy is not alive, return the max value of uint16.
// implements C.Proxy
func (p *Proxy) LastMeanDelay() (meanDelay uint16) {
	if proxy := p.ProxyAdapter.Unwrap(nil, false); proxy != nil {
		return proxy.LastMeanDelay()
	}
	var max uint16 = 0xffff
	if !p.alive.Load() {
		return max
	}

	last := p.history.Last()
	if last == nil {
		return max
	}
	history := last.(C.DelayHistory)
	if history.MeanDelay == 0 {
		return max
	}
	return history.MeanDelay
}

// MarshalJSON implements C.ProxyAdapter
func (p *Proxy) MarshalJSON() ([]byte, error) {
	inner, err := p.ProxyAdapter.MarshalJSON()
	if err != nil {
		return inner, err
	}

	mapping := map[string]any{}
	json.Unmarshal(inner, &mapping)
	mapping["history"] = p.DelayHistory()
	mapping["alive"] = p.Alive()
	mapping["name"] = p.Name()
	mapping["udp"] = p.SupportUDP()
	return json.Marshal(mapping)
}

// URLTest get the delay for the specified URL
// implements C.Proxy
func (p *Proxy) URLTest(ctx context.Context, url string) (delay, meanDelay uint16, err error) {
	if p.ignoreURLTest {
		return p.LastDelay(), p.LastMeanDelay(), nil
	}
	if proxy := p.ProxyAdapter.Unwrap(nil, true); proxy != nil {
		return proxy.URLTest(ctx, url)
	}
	defer func() {
		p.alive.Store(err == nil)
		record := C.DelayHistory{Time: time.Now()}
		if err == nil {
			record.Delay = delay
			record.MeanDelay = meanDelay
		}
		p.history.Put(record)
		if p.history.Len() > 10 {
			p.history.Pop()
		}
	}()

	if len(healthCheckURL) > 0 {
		url = healthCheckURL
	}

	addr, err := urlToMetadata(url)
	if err != nil {
		return
	}

	start := time.Now()
	instance, err := p.DialContext(ctx, &addr)
	if err != nil {
		return
	}
	defer instance.Close()

	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return
	}
	req = req.WithContext(ctx)

	transport := &http.Transport{
		Dial: func(string, string) (net.Conn, error) {
			return instance, nil
		},
		// from http.DefaultTransport
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       ca.GetGlobalTLSConfig(&tls.Config{}),
	}

	client := http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections()

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
	delay = uint16(time.Since(start) / time.Millisecond)

	resp, err = client.Do(req)
	if err != nil {
		// ignore error because some server will hijack the connection and close immediately
		return delay, 0, nil
	}
	resp.Body.Close()
	meanDelay = uint16(time.Since(start) / time.Millisecond / 2)

	return
}

func NewProxy(adapter C.ProxyAdapter) *Proxy {
	return &Proxy{adapter, queue.New(10), atomic.NewBool(true), false}
}

func NewProxyFromGroup(adapter C.ProxyAdapter, ignoreURLTest bool) *Proxy {
	return &Proxy{adapter, queue.New(10), atomic.NewBool(true), ignoreURLTest}
}

func urlToMetadata(rawURL string) (addr C.Metadata, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			err = fmt.Errorf("%s scheme not Support", rawURL)
			return
		}
	}
	uintPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return
	}

	addr = C.Metadata{
		Host:    u.Hostname(),
		DstPort: uint16(uintPort),
	}
	return
}

var healthCheckURL string

func HealthCheckURL() string {
	return healthCheckURL
}

func SetHealthCheckURL(newHealthCheckURL string) {
	healthCheckURL = newHealthCheckURL
}
