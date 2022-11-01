package outboundgroup

import (
	"regexp"
	"strings"
	"time"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
	"github.com/Dreamacro/clash/tunnel"
)

const (
	defaultGetProxiesDuration = time.Second * 5
)

func touchProviders(providers []provider.ProxyProvider) {
	for _, provider := range providers {
		provider.Touch()
	}
}

func getProvidersProxies(providers []provider.ProxyProvider, touch bool, filter string) []C.Proxy {
	proxies := []C.Proxy{}
	for _, provider := range providers {
		if touch {
			provider.Touch()
		}
		proxies = append(proxies, provider.Proxies()...)
	}
	matchedProxies := []C.Proxy{}
	if len(filter) > 0 {
		var filterRegs []*regexp.Regexp
		for _, filter := range strings.Split(filter, "`") {
			filterReg, err := regexp.Compile(filter)
			if err != nil {
				continue
			}
			filterRegs = append(filterRegs, filterReg)
		}
		proxiesSet := map[string]struct{}{}
		for _, filterReg := range filterRegs {
			for _, p := range proxies {
				if name := p.Name(); filterReg.MatchString(name) {
					if _, ok := proxiesSet[name]; !ok {
						proxiesSet[name] = struct{}{}
						matchedProxies = append(matchedProxies, p)
					}
				}
			}
		}
		// if no proxy matched, means bad filter, return all proxies
		if len(matchedProxies) > 0 {
			proxies = matchedProxies
		}
	}

	if len(proxies) == 0 {
		return []C.Proxy{tunnel.Proxies()["REJECT"]}
	}
	return proxies
}

func doHealthCheck(providers []provider.ProxyProvider, proxy C.Proxy) {
	for _, proxyProvider := range providers {
		for _, proxy2 := range proxyProvider.Proxies() {
			if proxy == proxy2 {
				go proxyProvider.HealthCheck()
			}
		}
	}
}
