package executor

import (
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"sync"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/component/auth"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	mihomoHttp "github.com/metacubex/mihomo/component/http"
	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/component/profile"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/component/profile/cachefileplain"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/resource"
	"github.com/metacubex/mihomo/component/sniffer"
	"github.com/metacubex/mihomo/component/trie"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	providerTypes "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/listener"
	authStore "github.com/metacubex/mihomo/listener/auth"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
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

// ApplyConfig dispatch configure to all parts without ExternalController
func ApplyConfig(cfg *config.Config, force bool) {
	mux.Lock()
	defer mux.Unlock()

	ca.ResetCertificate()
	for _, c := range cfg.TLS.CustomTrustCert {
		if err := ca.AddCertificate(c); err != nil {
			log.Warnln("%s\nadd error: %s", c, err.Error())
		}
	}

	updateExperimental(cfg.Experimental)
	updateUsers(cfg.Users)
	updateProxies(cfg.Proxies, cfg.Providers)
	updateRules(cfg.Rules, cfg.SubRules, cfg.RuleProviders)
	updateSniffer(cfg.Sniffer)
	updateHosts(cfg.Hosts)
	updateProfile(cfg)
	updateGeneral(cfg.General, force)
	updateListeners(cfg.Listeners)
	updateDNS(cfg.DNS, cfg.RuleProviders)
	updateTun(cfg.General) // tun should not care "force"
	loadProvider(cfg.Providers)
	loadProvider(cfg.RuleProviders)
	updateTunnels(cfg.Tunnels)

	resolver.ResetConnection()
	runtime.GC()
}

func GetGeneral() *config.General {
	ports := listener.GetPorts()
	authenticator := []string{}
	if auth := authStore.Default.Authenticator(); auth != nil {
		authenticator = auth.Users()
	}

	general := &config.General{
		Inbound: config.Inbound{
			Port:              ports.Port,
			SocksPort:         ports.SocksPort,
			RedirPort:         ports.RedirPort,
			TProxyPort:        ports.TProxyPort,
			MixedPort:         ports.MixedPort,
			Tun:               listener.GetTunConf(),
			TuicServer:        listener.GetTuicConf(),
			MixECConfig:       ports.MixECConfig,
			ShadowSocksConfig: ports.ShadowSocksConfig,
			VmessConfig:       ports.VmessConfig,
			MTProxyConfig:     ports.MTProxyConfig,
			Authentication:    authenticator,
			SkipAuthPrefixes:  inbound.SkipAuthPrefixes(),
			LanAllowedIPs:     inbound.AllowedIPs(),
			LanDisAllowedIPs:  inbound.DisAllowedIPs(),
			AllowLan:          listener.AllowLan(),
			BindAddress:       listener.BindAddress(),
			InboundTfo:        inbound.Tfo(),
			InboundMPTCP:      inbound.MPTCP(),
		},
		Mode:                   tunnel.Mode(),
		LogLevel:               log.Level(),
		IPv6:                   !resolver.DisableIPv6,
		Interface:              dialer.DefaultInterface.Load(),
		RoutingMark:            int(dialer.DefaultRoutingMark.Load()),
		HealthCheckURL:         adapter.HealthCheckURL(),
		HealthCheckLazyDefault: provider.HealthCheckLazyDefault(),
		TouchAfterLazyPassNum:  provider.TouchAfterLazyPassNum(),
		PreResolveProcessName:  tunnel.PreResolveProcessName(),
		TCPConcurrent:          dialer.GetTcpConcurrent(),
		GlobalUA:               mihomoHttp.UA(),
		ETagSupport:            resource.ETag(),
	}

	return general
}

func loadProvider[P providerTypes.Provider](providers map[string]P) {
	load := func(pv P) {
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

	// limit concurrent size
	wg := sync.WaitGroup{}
	ch := make(chan struct{}, concurrentCount)
	for _, _provider := range providers {
		_provider := _provider
		wg.Add(1)
		ch <- struct{}{}
		go func() {
			defer func() { <-ch; wg.Done() }()
			load(_provider)
		}()
	}

	wg.Wait()
}

func updateListeners(listeners map[string]C.InboundListener) {
	listener.PatchInboundListeners(listeners, tunnel.Tunnel, true)
}

func updateExperimental(c *config.Experimental) {
	if c.QUICGoDisableGSO {
		_ = os.Setenv("QUIC_GO_DISABLE_GSO", strconv.FormatBool(true))
	}
	if c.QUICGoDisableECN {
		_ = os.Setenv("QUIC_GO_DISABLE_ECN", strconv.FormatBool(true))
	}
}

func updateDNS(c *config.DNS, ruleProvider map[string]providerTypes.RuleProvider) {
	if !c.Enable {
		resolver.DefaultResolver = nil
		resolver.DefaultHostMapper = nil
		resolver.DefaultLocalServer = nil
		dns.ReCreateServer("", nil, nil)
		return
	}

	cfg := dns.Config{
		Main:                 c.NameServer,
		Fallback:             c.Fallback,
		IPv6:                 c.IPv6,
		EnhancedMode:         c.EnhancedMode,
		Pool:                 c.FakeIPRange,
		Hosts:                c.Hosts,
		FallbackIPFilter:     c.FallbackIPFilter,
		FallbackDomainFilter: c.FallbackDomainFilter,
		Default:              c.DefaultNameserver,
		Policy:               c.NameServerPolicy,
		ProxyServer:          c.ProxyServerNameserver,
		Tunnel:               tunnel.Tunnel,
		RuleProviders:        ruleProvider,
		SearchDomains:        c.SearchDomains,
		CacheAlgorithm:       c.CacheAlgorithm,
	}

	r, pr := dns.NewResolver(cfg)
	m := dns.NewEnhancer(cfg)

	// reuse cache of old host mapper
	if old := resolver.DefaultHostMapper; old != nil {
		m.PatchFrom(old.(*dns.ResolverEnhancer))
	}

	resolver.DefaultResolver = r
	resolver.DefaultHostMapper = m
	resolver.DefaultLocalServer = dns.NewLocalServer(r, m)

	if pr.Invalid() {
		resolver.ProxyServerHostResolver = pr
	}

	dns.ReCreateServer(c.Listen, r, m)
}

func updateHosts(tree *trie.DomainTrie[netip.Addr]) {
	resolver.DefaultHosts = tree
}

func updateProxies(proxies map[string]C.Proxy, providers map[string]providerTypes.ProxyProvider) {
	tunnel.UpdateProxies(proxies, providers)
}

func updateRules(rules []C.Rule, subRules map[string][]C.Rule, providers map[string]providerTypes.RuleProvider) {
	tunnel.UpdateRules(rules, subRules, providers)
}

func updateTun(general *config.General) {
	if general == nil {
		return
	}
	listener.ReCreateTun(general.Tun, tunnel.Tunnel)
}

func updateSniffer(snifferConfig *sniffer.Config) {
	dispatcher, err := sniffer.NewDispatcher(snifferConfig)
	if err != nil {
		log.Warnln("initial sniffer failed, err:%v", err)
	}

	tunnel.UpdateSniffer(dispatcher)

	if snifferConfig.Enable {
		log.Infoln("Sniffer is loaded and working")
	} else {
		log.Infoln("Sniffer is closed")
	}
}

func updateTunnels(tunnels []LC.Tunnel) {
	listener.PatchTunnel(tunnels, tunnel.Tunnel)
}

func updateGeneral(general *config.General, force bool) {
	log.SetLevel(general.LogLevel)
	tunnel.SetMode(general.Mode)
	resolver.DisableIPv6 = !general.IPv6
	adapter.SetHealthCheckURL(general.HealthCheckURL)
	provider.SetHealthCheckLazyDefault(general.HealthCheckLazyDefault)
	provider.SetTouchAfterLazyPassNum(general.TouchAfterLazyPassNum)
	tunnel.SetPreResolveProcessName(general.PreResolveProcessName)
	if general.TCPConcurrent {
		dialer.SetTcpConcurrent(general.TCPConcurrent)
		log.Infoln("Use tcp concurrent")
	}

	inbound.SetTfo(general.InboundTfo)
	inbound.SetMPTCP(general.InboundMPTCP)
	dialer.DefaultInterface.Store(general.Interface)
	dialer.GeneralInterface.Store(general.Interface)
	dialer.DefaultRoutingMark.Store(int32(general.RoutingMark))

	iface.FlushCache()

	if !force {
		return
	}

	allowLan := general.AllowLan
	listener.SetAllowLan(allowLan)
	inbound.SetSkipAuthPrefixes(general.SkipAuthPrefixes)
	inbound.SetAllowedIPs(general.LanAllowedIPs)
	inbound.SetDisAllowedIPs(general.LanDisAllowedIPs)

	bindAddress := general.BindAddress
	listener.SetBindAddress(bindAddress)

	listener.ReCreateHTTP(general.Port, tunnel.Tunnel)
	listener.ReCreateSocks(general.SocksPort, tunnel.Tunnel)
	listener.ReCreateRedir(general.RedirPort, tunnel.Tunnel)
	listener.ReCreateTProxy(general.TProxyPort, tunnel.Tunnel)
	listener.ReCreateMixed(general.MixedPort, tunnel.Tunnel)
	listener.ReCreateMixEC(general.MixECConfig, tunnel.Tunnel)
	listener.ReCreateShadowSocks(general.ShadowSocksConfig, tunnel.Tunnel)
	listener.ReCreateVmess(general.VmessConfig, tunnel.Tunnel)
	listener.ReCreateMTProxy(general.MTProxyConfig, tunnel.Tunnel)
	listener.ReCreateTuic(general.TuicServer, tunnel.Tunnel)
}

func updateUsers(users []auth.AuthUser) {
	authenticator := auth.NewAuthenticator(users)
	authStore.Default.SetAuthenticator(authenticator)
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

		selector.ForceSet(selected)
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

		selector.ForceSet(selected)
	}
}

func Shutdown() {
	listener.Cleanup()
	resolver.StoreFakePoolState()

	log.Warnln("Mihomo shutting down")
}
