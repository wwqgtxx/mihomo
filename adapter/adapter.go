package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/Dreamacro/clash/common/queue"
	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"

	"go.uber.org/atomic"
)

type Proxy struct {
	C.ProxyAdapter
	history       *queue.Queue
	alive         *atomic.Bool
	ignoreURLTest bool
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
	return aliveContext(p, ctx, func(ctx context.Context) (C.Conn, error) {
		return p.ProxyAdapter.DialContext(ctx, metadata, opts...)
	})
}

// DialUDP implements C.ProxyAdapter
func (p *Proxy) DialUDP(metadata *C.Metadata) (C.PacketConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultUDPTimeout)
	defer cancel()
	return p.ListenPacketContext(ctx, metadata)
}

// ListenPacketContext implements C.ProxyAdapter
func (p *Proxy) ListenPacketContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (C.PacketConn, error) {
	return aliveContext(p, ctx, func(ctx context.Context) (C.PacketConn, error) {
		return p.ProxyAdapter.ListenPacketContext(ctx, metadata, opts...)
	})
}

func aliveContext[T any](p *Proxy, ctx context.Context, f func(context.Context) (T, error)) (T, error) {
	beginTime := time.Now()
	t, err := f(ctx)
	timeUsed := time.Now().Sub(beginTime)
	if err != nil {
		if ctx.Err() == nil || timeUsed > 1*time.Second { // context not cancelled or timeUsed>1s
			p.alive.Store(false)
		}
	}
	return t, err
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

// MarshalJSON implements C.ProxyAdapter
func (p *Proxy) MarshalJSON() ([]byte, error) {
	inner, err := p.ProxyAdapter.MarshalJSON()
	if err != nil {
		return inner, err
	}

	mapping := map[string]any{}
	json.Unmarshal(inner, &mapping)
	mapping["history"] = p.DelayHistory()
	mapping["name"] = p.Name()
	mapping["udp"] = p.SupportUDP()
	return json.Marshal(mapping)
}

// URLTest get the delay for the specified URL
// implements C.Proxy
func (p *Proxy) URLTest(ctx context.Context, url string) (t uint16, err error) {
	if p.ignoreURLTest {
		return p.LastDelay(), nil
	}
	if proxy := p.ProxyAdapter.Unwrap(nil, true); proxy != nil {
		return proxy.URLTest(ctx, url)
	}
	defer func() {
		p.alive.Store(err == nil)
		record := C.DelayHistory{Time: time.Now()}
		if err == nil {
			record.Delay = t
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
	t = uint16(time.Since(start) / time.Millisecond)
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

	addr = C.Metadata{
		Host:    u.Hostname(),
		DstPort: port,
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
