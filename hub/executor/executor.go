package executor

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"sync"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/component/auth"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/component/profile"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/component/profile/cachefileplain"
	"github.com/metacubex/mihomo/component/resolver"
	SNI "github.com/metacubex/mihomo/component/sniffer"
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

// ApplyConfig dispatch configure to all parts
func ApplyConfig(cfg *config.Config, force bool) {
	mux.Lock()
	defer mux.Unlock()

	ca.ResetCertificate()
	for _, c := range cfg.TLS.CustomTrustCert {
		if err := ca.AddCertificate(c); err != nil {
			log.Warnln("%s\nadd error: %s", c, err.Error())
		}
	}

	updateUsers(cfg.Users)
	updateProxies(cfg.Proxies, cfg.Providers)
	updateRules(cfg.Rules, cfg.SubRules, cfg.RuleProviders)
	updateSniffer(cfg.Sniffer)
	updateHosts(cfg.Hosts)
	updateProfile(cfg)
	updateGeneral(cfg.General, force)
	updateListeners(cfg.Listeners)
	updateDNS(cfg.DNS, cfg.RuleProviders)
	updateTun(cfg.General)
	updateExperimental(cfg)
	loadProvider(cfg.RuleProviders, cfg.Providers)
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
		TCPConcurrent:          dialer.GetTcpConcurrent(),
	}

	return general
}

func loadProvider(ruleProviders map[string]providerTypes.RuleProvider, proxyProviders map[string]providerTypes.ProxyProvider) {
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

func updateListeners(listeners map[string]C.InboundListener) {
	listener.PatchInboundListeners(listeners, tunnel.Tunnel, true)
}

func updateExperimental(c *config.Config) {
	tunnel.UDPFallbackMatch.Store(c.Experimental.UDPFallbackMatch)
	if c.Experimental.QUICGoDisableGSO {
		_ = os.Setenv("QUIC_GO_DISABLE_GSO", strconv.FormatBool(true))
	}
	if c.Experimental.QUICGoDisableECN {
		_ = os.Setenv("QUIC_GO_DISABLE_ECN", strconv.FormatBool(true))
	}
}

func updateDNS(c *config.DNS, ruleProvider map[string]providerTypes.RuleProvider) {
	if !c.Enable {
		resolver.DialerResolver = nil
		resolver.DefaultResolver = nil
		resolver.DefaultHostMapper = nil
		resolver.DefaultLocalServer = nil
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
		Default:       c.DefaultNameserver,
		Policy:        c.NameServerPolicy,
		RuleProviders: ruleProvider,
		SearchDomains: c.SearchDomains,
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
	resolver.DefaultLocalServer = dns.NewLocalServer(r, m)

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

func updateRules(rules []C.Rule, subRules map[string][]C.Rule, providers map[string]providerTypes.RuleProvider) {
	tunnel.UpdateRules(rules, subRules, providers)
}

func updateTun(general *config.General) {
	if general == nil {
		return
	}
	listener.ReCreateTun(general.Tun, tunnel.Tunnel)
}

func updateSniffer(sniffer *config.Sniffer) {
	if sniffer.Enable {
		dispatcher, err := SNI.NewSnifferDispatcher(
			sniffer.Sniffers, sniffer.ForceDomain, sniffer.SkipDomain,
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

func updateTunnels(tunnels []LC.Tunnel) {
	listener.PatchTunnel(tunnels, tunnel.Tunnel)
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

func CleanUp() {
	listener.CleanUp()
}
