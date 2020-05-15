package outboundgroup

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"math/big"

	"github.com/wwqgtxx/clashr/adapters/outbound"
	"github.com/wwqgtxx/clashr/adapters/provider"
	"github.com/wwqgtxx/clashr/common/singledo"
	C "github.com/wwqgtxx/clashr/constant"
)

type LoadBalanceR struct {
	*outbound.Base
	single    *singledo.Single
	providers []provider.ProxyProvider
}

func (lb *LoadBalanceR) DialContext(ctx context.Context, metadata *C.Metadata) (c C.Conn, err error) {
	defer func() {
		if err == nil {
			c.AppendToChains(lb)
		}
	}()

	proxy := lb.Unwrap(metadata)

	c, err = proxy.DialContext(ctx, metadata)
	return
}

func (lb *LoadBalanceR) DialUDP(metadata *C.Metadata) (pc C.PacketConn, err error) {
	defer func() {
		if err == nil {
			pc.AppendToChains(lb)
		}
	}()

	proxy := lb.Unwrap(metadata)

	return proxy.DialUDP(metadata)
}

func (lb *LoadBalanceR) SupportUDP() bool {
	return true
}

func (lb *LoadBalanceR) Unwrap(metadata *C.Metadata) C.Proxy {
	proxies := lb.proxies()
	aliveProxies := make([]C.Proxy, 0, len(proxies))
	for _, proxy := range proxies {
		if proxy.Alive() {
			aliveProxies = append(aliveProxies, proxy)
		}
	}
	aliveNum := int64(len(aliveProxies))
	if aliveNum == 0 {
		return proxies[0]
	}
	idx, err := rand.Int(rand.Reader, big.NewInt(aliveNum))
	if err != nil {
		return aliveProxies[0]
	}

	return aliveProxies[idx.Int64()]
}

func (lb *LoadBalanceR) proxies() []C.Proxy {
	elm, _, _ := lb.single.Do(func() (interface{}, error) {
		return getProvidersProxies(lb.providers), nil
	})

	return elm.([]C.Proxy)
}

func (lb *LoadBalanceR) MarshalJSON() ([]byte, error) {
	var all []string
	for _, proxy := range lb.proxies() {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]interface{}{
		"type": lb.Type().String(),
		"all":  all,
	})
}

func NewLoadBalanceR(name string, providers []provider.ProxyProvider) *LoadBalanceR {
	return &LoadBalanceR{
		Base:      outbound.NewBase(name, "", C.LoadBalanceR, false),
		single:    singledo.NewSingle(defaultGetProxiesDuration),
		providers: providers,
	}
}
