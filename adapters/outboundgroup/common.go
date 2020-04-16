package outboundgroup

import (
	"time"

	"github.com/wwqgtxx/clashr/adapters/provider"
	C "github.com/wwqgtxx/clashr/constant"
)

const (
	defaultGetProxiesDuration = time.Second * 5
)

func getProvidersProxies(providers []provider.ProxyProvider) []C.Proxy {
	proxies := []C.Proxy{}
	for _, provider := range providers {
		proxies = append(proxies, provider.Proxies()...)
	}
	return proxies
}
