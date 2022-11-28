package executor

import (
	"fmt"
	"net/netip"
	"os"
	"sync"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/adapter/outboundgroup"
	"github.com/Dreamacro/clash/adapter/provider"
	"github.com/Dreamacro/clash/component/auth"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/iface"
	"github.com/Dreamacro/clash/component/profile"
	"github.com/Dreamacro/clash/component/profile/cachefile"
	"github.com/Dreamacro/clash/component/profile/cachefileplain"
	"github.com/Dreamacro/clash/component/resolver"
	SNI "github.com/Dreamacro/clash/component/sniffer"
	"github.com/Dreamacro/clash/component/trie"
	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	providerTypes "github.com/Dreamacro/clash/constant/provider"
	"github.com/Dreamacro/clash/dns"
	"github.com/Dreamacro/clash/listener"
	authStore "github.com/Dreamacro/clash/listener/auth"
	"github.com/Dreamacro/clash/log"
	R "github.com/Dreamacro/clash/rule"
	"github.com/Dreamacro/clash/tunnel"
)

var mux sync.Mutex

func readConfig(path string) ([]byte, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("configuration file %s is empty", path)
	}

	return data, err
}

// Parse config with default config path
func Parse() (*config.Config, error) {
	return ParseWithPath(C.Path.Config())
}

// ParseWithPath parse config with custom config path
func ParseWithPath(path string) (*config.Config, error) {
	buf, err := readConfig(path)
	if err != nil {
		return nil, err
	}

	return ParseWithBytes(buf)
}

// ParseWithBytes config with buffer
func ParseWithBytes(buf []byte) (*config.Config, error) {
	return config.Parse(buf)
}

// ApplyConfig dispatch configure to all parts
func ApplyConfig(cfg *config.Config, force bool) {
	mux.Lock()
	defer mux.Unlock()

	updateUsers(cfg.Users)
	updateProxies(cfg.Proxies, cfg.Providers)
	updateRules(cfg.Rules, cfg.RulesProviders)
	updateSniffer(cfg.Sniffer)
	updateHosts(cfg.Hosts)
	updateProfile(cfg)
	updateGeneral(cfg.General, force)
	updateDNS(cfg.DNS)
	updateTun(cfg.General)
	updateExperimental(cfg)
	loadProvider(cfg.RulesProviders, cfg.Providers)
	updateTunnels(cfg.Tunnels)
}

func GetGeneral() *config.General {
	ports := listener.GetPorts()
	authenticator := []string{}
	if auth := authStore.Authenticator(); auth != nil {
		authenticator = auth.Users()
	}

	general := &config.General{
		Inbound: config.Inbound{
			Port:              ports.Port,
			SocksPort:         ports.SocksPort,
			RedirPort:         ports.RedirPort,
			MixedPort:         ports.MixedPort,
			Tun:               listener.Tun(),
			MixECConfig:       ports.MixECConfig,
			TProxyPort:        ports.TProxyPort,
			ShadowSocksConfig: ports.ShadowSocksConfig,
			VmessConfig:       ports.VmessConfig,
			MTProxyConfig:     ports.MTProxyConfig,
			Authentication:    authenticator,
			AllowLan:          listener.AllowLan(),
			BindAddress:       listener.BindAddress(),
		},
		Mode:                   tunnel.Mode(),
		LogLevel:               log.Level(),
		IPv6:                   !resolver.DisableIPv6,
		UseRemoteDnsDefault:    dns.UseRemoteDnsDefault(),
		UseSystemDnsDial:       dns.UseSystemDnsDial(),
		HealthCheckURL:         adapter.HealthCheckURL(),
		HealthCheckLazyDefault: provider.HealthCheckLazyDefault(),
		TouchAfterLazyPassNum:  provider.TouchAfterLazyPassNum(),
		PreResolveProcessName:  tunnel.PreResolveProcessName(),
		TCPConcurrent:          dialer.GetDial(),
	}

	return general
}

func loadProvider(ruleProviders map[string]R.RuleProvider, proxyProviders map[string]providerTypes.ProxyProvider) {
	load := func(pv providerTypes.Provider) {
		if pv.VehicleType() == providerTypes.Compatible {
			log.Infoln("Start initial compatible provider %s", pv.Name())
		} else {
			log.Infoln("Start initial provider %s", (pv).Name())
		}

		if err := (pv).Initial(); err != nil {
			switch pv.Type() {
			case providerTypes.Proxy:
				{
					log.Warnln("initial proxy provider %s error: %v", (pv).Name(), err)
				}
			case providerTypes.Rule:
				{
					log.Warnln("initial rule provider %s error: %v", (pv).Name(), err)
				}

			}
		}
	}

	for _, proxyProvider := range proxyProviders {
		load(proxyProvider)
	}

	for _, ruleProvider := range ruleProviders {
		load(ruleProvider)
	}
}

func updateExperimental(c *config.Config) {}

func updateDNS(c *config.DNS) {
	if !c.Enable {
		resolver.DialerResolver = nil
		resolver.DefaultResolver = nil
		resolver.DefaultHostMapper = nil
		dns.ReCreateServer("", nil, nil)
		return
	}

	cfg := dns.Config{
		Main:         c.NameServer,
		Fallback:     c.Fallback,
		IPv6:         c.IPv6,
		EnhancedMode: c.EnhancedMode,
		Pool:         c.FakeIPRange,
		Hosts:        c.Hosts,
		FallbackFilter: dns.FallbackFilter{
			GeoIP:     c.FallbackFilter.GeoIP,
			GeoIPCode: c.FallbackFilter.GeoIPCode,
			IPCIDR:    c.FallbackFilter.IPCIDR,
			Domain:    c.FallbackFilter.Domain,
		},
		Default: c.DefaultNameserver,
		Policy:  c.NameServerPolicy,
	}

	dr, r := dns.NewResolver(cfg)
	m := dns.NewEnhancer(cfg)

	// reuse cache of old host mapper
	if old := resolver.DefaultHostMapper; old != nil {
		m.PatchFrom(old.(*dns.ResolverEnhancer))
	}

	resolver.DialerResolver = dr
	resolver.DefaultResolver = r
	resolver.DefaultHostMapper = m

	if dns.UseSystemDnsDial() {
		resolver.DialerResolver = nil
	}

	dns.ReCreateServer(c.Listen, r, m)
}

func updateHosts(tree *trie.DomainTrie[netip.Addr]) {
	resolver.DefaultHosts = tree
}

func updateProxies(proxies map[string]C.Proxy, providers map[string]providerTypes.ProxyProvider) {
	tunnel.UpdateProxies(proxies, providers)
}

func updateRules(rules []C.Rule, providers map[string]R.RuleProvider) {
	tunnel.UpdateRules(rules, providers)
}

func updateTun(general *config.General) {
	if general == nil {
		return
	}
	tcpIn := tunnel.TCPIn()
	udpIn := tunnel.UDPIn()
	listener.ReCreateTun(general.Tun, tcpIn, udpIn)
}

func updateSniffer(sniffer *config.Sniffer) {
	if sniffer.Enable {
		dispatcher, err := SNI.NewSnifferDispatcher(
			sniffer.Sniffers, sniffer.ForceDomain, sniffer.SkipDomain, sniffer.Ports,
			sniffer.ForceDnsMapping, sniffer.ParsePureIp,
		)
		if err != nil {
			log.Warnln("initial sniffer failed, err:%v", err)
		}

		tunnel.UpdateSniffer(dispatcher)
		log.Infoln("Sniffer is loaded and working")
	} else {
		dispatcher, err := SNI.NewCloseSnifferDispatcher()
		if err != nil {
			log.Warnln("initial sniffer failed, err:%v", err)
		}

		tunnel.UpdateSniffer(dispatcher)
		log.Infoln("Sniffer is closed")
	}
}

func updateTunnels(tunnels []config.Tunnel) {
	listener.PatchTunnel(tunnels, tunnel.TCPIn(), tunnel.UDPIn())
}

func updateGeneral(general *config.General, force bool) {
	log.SetLevel(general.LogLevel)
	tunnel.SetMode(general.Mode)
	resolver.DisableIPv6 = !general.IPv6
	dns.SetUseRemoteDnsDefault(general.UseRemoteDnsDefault)
	dns.SetUseSystemDnsDial(general.UseSystemDnsDial)
	adapter.SetHealthCheckURL(general.HealthCheckURL)
	provider.SetHealthCheckLazyDefault(general.HealthCheckLazyDefault)
	provider.SetTouchAfterLazyPassNum(general.TouchAfterLazyPassNum)
	tunnel.SetPreResolveProcessName(general.PreResolveProcessName)
	if general.TCPConcurrent {
		dialer.SetDial(general.TCPConcurrent)
		log.Infoln("Use tcp concurrent")
	}

	dialer.DefaultInterface.Store(general.Interface)
	dialer.GeneralInterface.Store(general.Interface)
	dialer.DefaultRoutingMark.Store(int32(general.RoutingMark))

	iface.FlushCache()

	if !force {
		return
	}

	allowLan := general.AllowLan
	listener.SetAllowLan(allowLan)

	bindAddress := general.BindAddress
	listener.SetBindAddress(bindAddress)

	tcpIn := tunnel.TCPIn()
	udpIn := tunnel.UDPIn()

	listener.ReCreateHTTP(general.Port, tcpIn)
	listener.ReCreateSocks(general.SocksPort, tcpIn, udpIn)
	listener.ReCreateRedir(general.RedirPort, tcpIn, udpIn)
	listener.ReCreateTProxy(general.TProxyPort, tcpIn, udpIn)
	listener.ReCreateMixed(general.MixedPort, tcpIn, udpIn)
	listener.ReCreateMixEC(general.MixECConfig, tcpIn, udpIn)
	listener.ReCreateShadowSocks(general.ShadowSocksConfig, tcpIn, udpIn)
	listener.ReCreateVmess(general.VmessConfig, tcpIn, udpIn)
	listener.ReCreateMTProxy(general.MTProxyConfig, tcpIn, udpIn)
	listener.ReCreateTuic(general.TuicServer, tcpIn, udpIn)
}

func updateUsers(users []auth.AuthUser) {
	authenticator := auth.NewAuthenticator(users)
	authStore.SetAuthenticator(authenticator)
	if authenticator != nil {
		log.Infoln("Authentication of local server updated")
	}
}

func updateProfile(cfg *config.Config) {
	profileCfg := cfg.Profile

	profile.StoreSelected.Store(profileCfg.StoreSelected)
	if profileCfg.StoreSelected {
		patchSelectGroup(cfg.Proxies)
		patchSelectGroupPlain(cfg.Proxies)
	}
}

func patchSelectGroup(proxies map[string]C.Proxy) {
	mapping := cachefile.Cache().SelectedMap()
	if mapping == nil {
		return
	}

	for name, proxy := range proxies {
		outbound, ok := proxy.(*adapter.Proxy)
		if !ok {
			continue
		}

		selector, ok := outbound.ProxyAdapter.(*outboundgroup.Selector)
		if !ok {
			continue
		}

		selected, exist := mapping[name]
		if !exist {
			continue
		}

		selector.Set(selected)
	}
}

func patchSelectGroupPlain(proxies map[string]C.Proxy) {
	mapping := cachefileplain.Cache().SelectedMap()
	if mapping == nil {
		return
	}

	for name, proxy := range proxies {
		outbound, ok := proxy.(*adapter.Proxy)
		if !ok {
			continue
		}

		selector, ok := outbound.ProxyAdapter.(*outboundgroup.Selector)
		if !ok {
			continue
		}

		selected, exist := mapping[name]
		if !exist {
			continue
		}

		selector.Set(selected)
	}
}

func CleanUp() {
	listener.CleanUp()
}
