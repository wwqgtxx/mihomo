package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Dreamacro/clash/adapter/outbound"
	"github.com/Dreamacro/clash/adapter/outboundgroup"
	"github.com/Dreamacro/clash/adapter/provider"
	"github.com/Dreamacro/clash/common/generics/utils"
	"github.com/Dreamacro/clash/component/auth"
	"github.com/Dreamacro/clash/component/fakeip"
	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"
	providerTypes "github.com/Dreamacro/clash/constant/provider"
	"github.com/Dreamacro/clash/constant/sniffer"
	snifferTypes "github.com/Dreamacro/clash/constant/sniffer"
	"github.com/Dreamacro/clash/dns"
	L "github.com/Dreamacro/clash/listener"
	LC "github.com/Dreamacro/clash/listener/config"
	"github.com/Dreamacro/clash/log"
	R "github.com/Dreamacro/clash/rule"
	T "github.com/Dreamacro/clash/tunnel"

	"gopkg.in/yaml.v3"
)

// General config
type General struct {
	Inbound
	Controller
	Mode                   T.TunnelMode `json:"mode"`
	LogLevel               log.LogLevel `json:"log-level"`
	IPv6                   bool         `json:"ipv6"`
	Interface              string       `json:"-"`
	RoutingMark            int          `json:"-"`
	UseRemoteDnsDefault    bool         `json:"use-remote-dns-default"`
	UseSystemDnsDial       bool         `json:"use-system-dns-dial"`
	HealthCheckURL         string       `json:"health-check-url"`
	HealthCheckLazyDefault bool         `json:"health-check-lazy-default"`
	TouchAfterLazyPassNum  int          `json:"touch-after-lazy-pass-num"`
	PreResolveProcessName  bool         `json:"pre-resolve-process-name"`
	TCPConcurrent          bool         `json:"tcp-concurrent"`
	Sniffing               bool         `json:"sniffing"`
}

// Inbound
type Inbound struct {
	Port              int           `json:"port"`
	SocksPort         int           `json:"socks-port"`
	RedirPort         int           `json:"redir-port"`
	TProxyPort        int           `json:"tproxy-port"`
	MixedPort         int           `json:"mixed-port"`
	Tun               LC.Tun        `json:"tun"`
	TuicServer        LC.TuicServer `json:"tuic-server"`
	MixECConfig       string        `json:"mixec-config"`
	ShadowSocksConfig string        `json:"ss-config"`
	VmessConfig       string        `json:"vmess-config"`
	MTProxyConfig     string        `json:"mtproxy-config"`
	Authentication    []string      `json:"authentication"`
	AllowLan          bool          `json:"allow-lan"`
	BindAddress       string        `json:"bind-address"`
	InboundTfo        bool          `json:"inbound-tfo"`
}

// Controller
type Controller struct {
	ExternalController string `json:"-"`
	ExternalUI         string `json:"-"`
	Secret             string `json:"-"`
}

// DNS config
type DNS struct {
	Enable            bool             `yaml:"enable"`
	IPv6              bool             `yaml:"ipv6"`
	NameServer        []dns.NameServer `yaml:"nameserver"`
	Fallback          []dns.NameServer `yaml:"fallback"`
	FallbackFilter    FallbackFilter   `yaml:"fallback-filter"`
	Listen            string           `yaml:"listen"`
	EnhancedMode      C.DNSMode        `yaml:"enhanced-mode"`
	DefaultNameserver []dns.NameServer `yaml:"default-nameserver"`
	FakeIPRange       *fakeip.Pool
	Hosts             *trie.DomainTrie[netip.Addr]
	NameServerPolicy  map[string]dns.NameServer
	SearchDomains     []string
}

// FallbackFilter config
type FallbackFilter struct {
	GeoIP     bool           `yaml:"geoip"`
	GeoIPCode string         `yaml:"geoip-code"`
	IPCIDR    []netip.Prefix `yaml:"ipcidr"`
	Domain    []string       `yaml:"domain"`
}

// Profile config
type Profile struct {
	StoreSelected bool `yaml:"store-selected"`
	StoreFakeIP   bool `yaml:"store-fake-ip"`
}

type Sniffer struct {
	Enable          bool
	Sniffers        []sniffer.Type
	ForceDomain     *trie.DomainSet
	SkipDomain      *trie.DomainSet
	Ports           *[]utils.Range[uint16]
	ForceDnsMapping bool
	ParsePureIp     bool
}

// Experimental config
type Experimental struct {
	UDPFallbackMatch bool `yaml:"udp-fallback-match"`
}

// Config is clash config manager
type Config struct {
	General        *General
	DNS            *DNS
	Experimental   *Experimental
	Hosts          *trie.DomainTrie[netip.Addr]
	Profile        *Profile
	Rules          []C.Rule
	SubRules       map[string][]C.Rule
	RulesProviders map[string]providerTypes.RuleProvider
	Users          []auth.AuthUser
	Proxies        map[string]C.Proxy
	Providers      map[string]providerTypes.ProxyProvider
	Listeners      map[string]C.InboundListener
	Tunnels        []LC.Tunnel
	Sniffer        *Sniffer
}

type RawDNS struct {
	Enable            bool              `yaml:"enable"`
	IPv6              bool              `yaml:"ipv6"`
	UseHosts          bool              `yaml:"use-hosts"`
	NameServer        []string          `yaml:"nameserver"`
	Fallback          []string          `yaml:"fallback"`
	FallbackFilter    RawFallbackFilter `yaml:"fallback-filter"`
	Listen            string            `yaml:"listen"`
	EnhancedMode      C.DNSMode         `yaml:"enhanced-mode"`
	FakeIPRange       string            `yaml:"fake-ip-range"`
	FakeIPFilter      []string          `yaml:"fake-ip-filter"`
	DefaultNameserver []string          `yaml:"default-nameserver"`
	NameServerPolicy  map[string]string `yaml:"nameserver-policy"`
	SearchDomains     []string          `yaml:"search-domains"`
}

type RawFallbackFilter struct {
	GeoIP     bool     `yaml:"geoip"`
	GeoIPCode string   `yaml:"geoip-code"`
	IPCIDR    []string `yaml:"ipcidr"`
	Domain    []string `yaml:"domain"`
}

type RawConfig struct {
	Port                   int          `yaml:"port"`
	SocksPort              int          `yaml:"socks-port"`
	RedirPort              int          `yaml:"redir-port"`
	TProxyPort             int          `yaml:"tproxy-port"`
	MixedPort              int          `yaml:"mixed-port"`
	MixECConfig            string       `yaml:"mixec-config"`
	ShadowSocksConfig      string       `yaml:"ss-config"`
	VmessConfig            string       `yaml:"vmess-config"`
	MTProxyConfig          string       `yaml:"mtproxy-config"`
	InboundTfo             bool         `yaml:"inbound-tfo"`
	Authentication         []string     `yaml:"authentication"`
	AllowLan               bool         `yaml:"allow-lan"`
	BindAddress            string       `yaml:"bind-address"`
	Mode                   T.TunnelMode `yaml:"mode"`
	LogLevel               log.LogLevel `yaml:"log-level"`
	IPv6                   bool         `yaml:"ipv6"`
	ExternalController     string       `yaml:"external-controller"`
	ExternalUI             string       `yaml:"external-ui"`
	Secret                 string       `yaml:"secret"`
	Interface              string       `yaml:"interface-name"`
	RoutingMark            int          `yaml:"routing-mark"`
	Tunnels                []LC.Tunnel  `yaml:"tunnels"`
	UseRemoteDnsDefault    bool         `yaml:"use-remote-dns-default"`
	UseSystemDnsDial       bool         `yaml:"use-system-dns-dial"`
	HealthCheckURL         string       `yaml:"health-check-url"`
	HealthCheckLazyDefault bool         `yaml:"health-check-lazy-default"`
	TouchAfterLazyPassNum  int          `yaml:"touch-after-lazy-pass-num"`
	PreResolveProcessName  bool         `yaml:"pre-resolve-process-name"`
	TCPConcurrent          bool         `yaml:"tcp-concurrent"`

	Sniffer       RawSniffer                `yaml:"sniffer"`
	RuleProviders map[string]map[string]any `yaml:"rule-providers"`
	ProxyProvider map[string]map[string]any `yaml:"proxy-providers"`
	Hosts         map[string]string         `yaml:"hosts"`
	DNS           RawDNS                    `yaml:"dns"`
	Tun           LC.Tun                    `yaml:"tun"`
	TuicServer    LC.TuicServer             `yaml:"tuic-server"`
	Experimental  Experimental              `yaml:"experimental"`
	Profile       Profile                   `yaml:"profile"`
	Proxy         []map[string]any          `yaml:"proxies"`
	ProxyGroup    []map[string]any          `yaml:"proxy-groups"`
	Rule          []string                  `yaml:"rules"`
	SubRules      map[string][]string       `yaml:"sub-rules"`
	Listeners     []map[string]any          `yaml:"listeners"`
}

type RawSniffer struct {
	Enable          bool     `yaml:"enable" json:"enable"`
	Sniffing        []string `yaml:"sniffing" json:"sniffing"`
	ForceDomain     []string `yaml:"force-domain" json:"force-domain"`
	SkipDomain      []string `yaml:"skip-domain" json:"skip-domain"`
	Ports           []string `yaml:"port-whitelist" json:"port-whitelist"`
	ForceDnsMapping bool     `yaml:"force-dns-mapping" json:"force-dns-mapping"`
	ParsePureIp     bool     `yaml:"parse-pure-ip" json:"parse-pure-ip"`
}

// Parse config
func Parse(buf []byte) (*Config, error) {
	rawCfg, err := UnmarshalRawConfig(buf)
	if err != nil {
		return nil, err
	}

	return ParseRawConfig(rawCfg)
}

func UnmarshalRawConfig(buf []byte) (*RawConfig, error) {
	// config with default value
	rawCfg := &RawConfig{
		InboundTfo:             true,
		AllowLan:               false,
		BindAddress:            "*",
		Mode:                   T.Rule,
		Authentication:         []string{},
		LogLevel:               log.INFO,
		UseRemoteDnsDefault:    true,
		UseSystemDnsDial:       false,
		HealthCheckURL:         "",
		HealthCheckLazyDefault: true,
		TouchAfterLazyPassNum:  0,
		PreResolveProcessName:  false,
		TCPConcurrent:          true,
		Hosts:                  map[string]string{},
		Rule:                   []string{},
		Proxy:                  []map[string]any{},
		ProxyGroup:             []map[string]any{},
		Tun: LC.Tun{
			Enable:              false,
			Stack:               C.TunSystem,
			DNSHijack:           []string{},
			AutoDetectInterface: true,
			AutoRoute:           true,
			Inet4Address:        []LC.ListenPrefix{LC.ListenPrefix(netip.MustParsePrefix("198.18.0.1/30"))},
			Inet6Address:        []LC.ListenPrefix{LC.ListenPrefix(netip.MustParsePrefix("fdfe:dcba:9876::1/126"))},
		},
		TuicServer: LC.TuicServer{
			Enable:                false,
			Token:                 nil,
			Certificate:           "",
			PrivateKey:            "",
			Listen:                "",
			CongestionController:  "",
			MaxIdleTime:           15000,
			AuthenticationTimeout: 1000,
			ALPN:                  []string{"h3"},
			MaxUdpRelayPacketSize: 1500,
		},
		Sniffer: RawSniffer{
			Enable:          true,
			Sniffing:        []string{snifferTypes.TLS.String(), snifferTypes.HTTP.String()},
			ForceDomain:     []string{},
			SkipDomain:      []string{},
			Ports:           []string{"80", "443"},
			ForceDnsMapping: true,
			ParsePureIp:     false,
		},
		DNS: RawDNS{
			Enable:      true,
			IPv6:        true,
			UseHosts:    true,
			FakeIPRange: "198.18.0.1/16",
			FallbackFilter: RawFallbackFilter{
				GeoIP:     true,
				GeoIPCode: "CN",
				IPCIDR:    []string{},
			},
			DefaultNameserver: []string{
				"114.114.114.114",
				"tcp://114.114.114.114",
				"223.5.5.5",
				"tcp://223.5.5.5",
				"8.8.8.8",
				"tcp://8.8.8.8",
				"1.0.0.1",
				"tcp://1.0.0.1",
			},
			NameServer: []string{
				"https://8.8.8.8/dns-query",
				"https://1.0.0.1/dns-query",
			},
			FakeIPFilter: []string{
				"dns.msftnsci.com",
				"www.msftnsci.com",
				"www.msftconnecttest.com",
			},
		},
		Profile: Profile{
			StoreSelected: true,
		},
	}

	if err := yaml.Unmarshal(buf, rawCfg); err != nil {
		return nil, err
	}

	return rawCfg, nil
}

func ParseRawConfig(rawCfg *RawConfig) (*Config, error) {
	config := &Config{}

	config.Experimental = &rawCfg.Experimental
	config.Profile = &rawCfg.Profile

	general, err := parseGeneral(rawCfg)
	if err != nil {
		return nil, err
	}
	config.General = general

	proxies, providers, err := parseProxies(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Proxies = proxies
	config.Providers = providers

	listener, err := parseListeners(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Listeners = listener

	ruleProviders, err := parseRuleProviders(rawCfg)
	if err != nil {
		return nil, err
	}
	config.RulesProviders = ruleProviders

	subRules, err := parseSubRules(rawCfg, proxies)
	if err != nil {
		return nil, err
	}
	config.SubRules = subRules

	rules, err := parseRules(rawCfg.Rule, proxies, subRules, "rules")
	if err != nil {
		return nil, err
	}
	config.Rules = rules

	hosts, err := parseHosts(rawCfg)
	if err != nil {
		return nil, err
	}
	config.Hosts = hosts

	dnsCfg, err := parseDNS(rawCfg, hosts)
	if err != nil {
		return nil, err
	}
	config.DNS = dnsCfg

	config.Users = parseAuthentication(rawCfg.Authentication)

	config.Tunnels = rawCfg.Tunnels
	// verify tunnels
	for _, t := range config.Tunnels {
		if len(t.Proxy) > 0 {
			if _, ok := config.Proxies[t.Proxy]; !ok {
				return nil, fmt.Errorf("tunnel proxy %s not found", t.Proxy)
			}
		}
	}

	config.Sniffer, err = parseSniffer(rawCfg.Sniffer)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func parseGeneral(cfg *RawConfig) (*General, error) {
	externalUI := cfg.ExternalUI

	// checkout externalUI exist
	if externalUI != "" {
		externalUI = C.Path.Resolve(externalUI)

		if _, err := os.Stat(externalUI); os.IsNotExist(err) {
			return nil, fmt.Errorf("external-ui: %s not exist", externalUI)
		}
	}

	return &General{
		Inbound: Inbound{
			Port:              cfg.Port,
			SocksPort:         cfg.SocksPort,
			RedirPort:         cfg.RedirPort,
			TProxyPort:        cfg.TProxyPort,
			MixedPort:         cfg.MixedPort,
			Tun:               cfg.Tun,
			TuicServer:        cfg.TuicServer,
			MixECConfig:       cfg.MixECConfig,
			ShadowSocksConfig: cfg.ShadowSocksConfig,
			VmessConfig:       cfg.VmessConfig,
			MTProxyConfig:     cfg.MTProxyConfig,
			AllowLan:          cfg.AllowLan,
			BindAddress:       cfg.BindAddress,
			InboundTfo:        cfg.InboundTfo,
		},
		Controller: Controller{
			ExternalController: cfg.ExternalController,
			ExternalUI:         cfg.ExternalUI,
			Secret:             cfg.Secret,
		},
		Mode:                   cfg.Mode,
		LogLevel:               cfg.LogLevel,
		IPv6:                   cfg.IPv6,
		Interface:              cfg.Interface,
		RoutingMark:            cfg.RoutingMark,
		UseRemoteDnsDefault:    cfg.UseRemoteDnsDefault,
		UseSystemDnsDial:       cfg.UseSystemDnsDial,
		HealthCheckURL:         cfg.HealthCheckURL,
		HealthCheckLazyDefault: cfg.HealthCheckLazyDefault,
		TouchAfterLazyPassNum:  cfg.TouchAfterLazyPassNum,
		PreResolveProcessName:  cfg.PreResolveProcessName,
		TCPConcurrent:          cfg.TCPConcurrent,
	}, nil
}

func parseProxies(cfg *RawConfig) (proxies map[string]C.Proxy, providersMap map[string]providerTypes.ProxyProvider, err error) {
	proxies = make(map[string]C.Proxy)
	providersMap = make(map[string]providerTypes.ProxyProvider)
	proxyList := []string{}
	proxiesConfig := cfg.Proxy
	groupsConfig := cfg.ProxyGroup
	providersConfig := cfg.ProxyProvider
	healthCheckLazyDefault := cfg.HealthCheckLazyDefault
	healthCheckURL := cfg.HealthCheckURL

	proxies["DIRECT"] = adapter.NewProxy(outbound.NewDirect())
	proxies["REJECT"] = adapter.NewProxy(outbound.NewReject())
	proxies["COMPATIBLE"] = adapter.NewProxy(outbound.NewCompatible())
	proxies["PASS"] = adapter.NewProxy(outbound.NewPass())
	proxyList = append(proxyList, "DIRECT", "REJECT")

	// parse proxy
	for idx, mapping := range proxiesConfig {
		proxy, err := adapter.ParseProxy(mapping)
		if err != nil {
			return nil, nil, fmt.Errorf("proxy %d: %w", idx, err)
		}

		if _, exist := proxies[proxy.Name()]; exist {
			return nil, nil, fmt.Errorf("proxy %s is the duplicate name", proxy.Name())
		}
		proxies[proxy.Name()] = proxy
		proxyList = append(proxyList, proxy.Name())
	}

	// keep the original order of ProxyGroups in config file
	for idx, mapping := range groupsConfig {
		groupName, existName := mapping["name"].(string)
		if !existName {
			return nil, nil, fmt.Errorf("proxy group %d: missing name", idx)
		}
		proxyList = append(proxyList, groupName)
	}

	// check if any loop exists and sort the ProxyGroups
	if err := proxyGroupsDagSort(groupsConfig); err != nil {
		return nil, nil, err
	}

	// parse and initial providers
	for name, mapping := range providersConfig {
		if name == provider.ReservedName {
			return nil, nil, fmt.Errorf("can not defined a provider called `%s`", provider.ReservedName)
		}

		pd, err := provider.ParseProxyProvider(name, mapping, healthCheckLazyDefault, healthCheckURL)
		if err != nil {
			return nil, nil, fmt.Errorf("parse proxy provider %s error: %w", name, err)
		}

		providersMap[name] = pd
	}

	// --------------------------------
	// merge to executor.loadProvider()
	// --------------------------------
	//for _, provider := range providersMap {
	//	log.Infoln("Start initial provider %s", provider.Name())
	//	if err := provider.Initial(); err != nil {
	//		return nil, nil, fmt.Errorf("initial proxy provider %s error: %w", provider.Name(), err)
	//	}
	//}

	// parse proxy group
	for idx, mapping := range groupsConfig {
		_, err := outboundgroup.ParseProxyGroup(mapping, proxies, providersMap, healthCheckLazyDefault)
		if err != nil {
			return nil, nil, fmt.Errorf("proxy group[%d]: %w", idx, err)
		}

		// --------------------------------
		// merge to outboundgroup.ParseProxyGroup()
		// --------------------------------
		//groupName := group.Name()
		//if _, exist := proxies[groupName]; exist {
		//	return nil, nil, fmt.Errorf("proxy group %s: the duplicate name", groupName)
		//}
		//
		//proxies[groupName] = adapter.NewProxy(group)
	}

	// --------------------------------
	// merge to executor.loadProvider()
	// --------------------------------
	// initial compatible provider
	//for _, pd := range providersMap {
	//	if pd.VehicleType() != providerTypes.Compatible {
	//		continue
	//	}
	//
	//	log.Infoln("Start initial compatible provider %s", pd.Name())
	//	if err := pd.Initial(); err != nil {
	//		return nil, nil, err
	//	}
	//}

	ps := []C.Proxy{}
	for _, v := range proxyList {
		if proxies[v].Type() == C.Pass {
			continue
		}
		ps = append(ps, proxies[v])
	}
	hc := provider.NewHealthCheck(ps, "", 0, true, provider.ReservedName, provider.ReservedName)
	pd, _ := provider.NewCompatibleProvider(provider.ReservedName, ps, hc)
	providersMap[provider.ReservedName] = pd

	global := outboundgroup.NewSelector(
		&outboundgroup.GroupCommonOption{
			Name: "GLOBAL",
		},
		[]providerTypes.ProxyProvider{pd},
	)
	proxies["GLOBAL"] = adapter.NewProxy(global)
	return proxies, providersMap, nil
}

func parseListeners(cfg *RawConfig) (listeners map[string]C.InboundListener, err error) {
	listeners = make(map[string]C.InboundListener)
	for index, mapping := range cfg.Listeners {
		listener, err := L.ParseListener(mapping)
		if err != nil {
			return nil, fmt.Errorf("proxy %d: %w", index, err)
		}

		if _, exist := mapping[listener.Name()]; exist {
			return nil, fmt.Errorf("listener %s is the duplicate name", listener.Name())
		}

		listeners[listener.Name()] = listener

	}
	return
}

func parseRuleProviders(cfg *RawConfig) (providersMap map[string]providerTypes.RuleProvider, err error) {
	providersMap = make(map[string]providerTypes.RuleProvider)
	providersConfig := cfg.RuleProviders

	// parse and initial providers
	for name, mapping := range providersConfig {
		rd, err := R.ParseRuleProvider(name, mapping)
		if err != nil {
			return nil, fmt.Errorf("parse rule ruleProvider %s error: %w", name, err)
		}

		providersMap[name] = rd
	}

	// --------------------------------
	// merge to executor.loadProvider()
	// --------------------------------
	//for _, ruleProvider := range providersMap {
	//	log.Infoln("Start initial ruleProvider %s", ruleProvider.Name())
	//	if err := ruleProvider.Initial(); err != nil {
	//		return nil, nil, fmt.Errorf("initial rule ruleProvider %s error: %w", ruleProvider.Name(), err)
	//	}
	//}

	return
}

func parseSubRules(cfg *RawConfig, proxies map[string]C.Proxy) (subRules map[string][]C.Rule, err error) {
	subRules = map[string][]C.Rule{}
	for name, rawRules := range cfg.SubRules {
		if len(name) == 0 {
			return nil, fmt.Errorf("sub-rule name is empty")
		}
		var rules []C.Rule
		rules, err = parseRules(rawRules, proxies, subRules, fmt.Sprintf("sub-rules[%s]", name))
		if err != nil {
			return nil, err
		}
		subRules[name] = rules
	}

	if err = verifySubRule(subRules); err != nil {
		return nil, err
	}

	return
}

func verifySubRule(subRules map[string][]C.Rule) error {
	for name := range subRules {
		err := verifySubRuleCircularReferences(name, subRules, []string{})
		if err != nil {
			return err
		}
	}
	return nil
}

func verifySubRuleCircularReferences(n string, subRules map[string][]C.Rule, arr []string) error {
	isInArray := func(v string, array []string) bool {
		for _, c := range array {
			if v == c {
				return true
			}
		}
		return false
	}

	arr = append(arr, n)
	for i, rule := range subRules[n] {
		if rule.RuleType() == C.SubRules {
			if _, ok := subRules[rule.Adapter()]; !ok {
				return fmt.Errorf("sub-rule[%d:%s] error: [%s] not found", i, n, rule.Adapter())
			}
			if isInArray(rule.Adapter(), arr) {
				arr = append(arr, rule.Adapter())
				return fmt.Errorf("sub-rule error: circular references [%s]", strings.Join(arr, "->"))
			}

			if err := verifySubRuleCircularReferences(rule.Adapter(), subRules, arr); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseRules(rulesConfig []string, proxies map[string]C.Proxy, subRules map[string][]C.Rule, format string) ([]C.Rule, error) {
	var rules []C.Rule

	// parse rules
	for idx, line := range rulesConfig {
		rule := trimArr(strings.Split(line, ","))
		var (
			payload  string
			target   string
			params   []string
			ruleName = strings.ToUpper(rule[0])
		)

		l := len(rule)

		if ruleName == "NOT" || ruleName == "OR" || ruleName == "AND" || ruleName == "SUB-RULE" {
			target = rule[l-1]
			payload = strings.Join(rule[1:l-1], ",")
		} else {
			if l < 2 {
				return nil, fmt.Errorf("%s[%d] [%s] error: format invalid", format, idx, line)
			}
			if l < 4 {
				rule = append(rule, make([]string, 4-l)...)
			}
			if ruleName == "MATCH" {
				l = 2
			}
			if l >= 3 {
				l = 3
				payload = rule[1]
			}
			target = rule[l-1]
			params = rule[l:]
		}
		if _, ok := proxies[target]; !ok {
			if ruleName != "SUB-RULE" {
				return nil, fmt.Errorf("%s[%d] [%s] error: proxy [%s] not found", format, idx, line, target)
			} else if _, ok = subRules[target]; !ok {
				return nil, fmt.Errorf("%s[%d] [%s] error: sub-rule [%s] not found", format, idx, line, target)
			}
		}

		params = trimArr(params)
		parsed, parseErr := R.ParseRule(ruleName, payload, target, params, subRules)
		if parseErr != nil {
			return nil, fmt.Errorf("%s[%d] [%s] error: %s", format, idx, line, parseErr.Error())
		}

		rules = append(rules, parsed)
	}

	return rules, nil
}

func parseHosts(cfg *RawConfig) (*trie.DomainTrie[netip.Addr], error) {
	tree := trie.New[netip.Addr]()

	// add default hosts
	if err := tree.Insert("localhost", netip.AddrFrom4([4]byte{127, 0, 0, 1})); err != nil {
		log.Errorln("insert localhost to host error: %s", err.Error())
	}

	if len(cfg.Hosts) != 0 {
		for domain, ipStr := range cfg.Hosts {
			ip, err := netip.ParseAddr(ipStr)
			if err != nil {
				return nil, fmt.Errorf("%s is not a valid IP", ipStr)
			}
			tree.Insert(domain, ip)
		}
	}
	tree.Optimize()

	return tree, nil
}

func hostWithDefaultPort(host string, defPort string) (string, error) {
	if !strings.Contains(host, ":") {
		host += ":"
	}

	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		return "", err
	}

	if port == "" {
		port = defPort
	}

	return net.JoinHostPort(hostname, port), nil
}

func parseNameServer(servers []string, useRemoteDnsDefault bool) ([]dns.NameServer, error) {
	nameservers := []dns.NameServer{}

	for idx, server := range servers {
		// parse remote dns request
		useRemote := strings.HasPrefix(server, "remote-")
		if useRemote {
			server = strings.TrimPrefix(server, "remote-")
		}
		if useRemoteDnsDefault {
			useRemote = true
		}

		// force use local
		useLocal := strings.HasPrefix(server, "local-")
		if useLocal {
			server = strings.TrimPrefix(server, "local-")
		}
		if useLocal {
			useRemote = false
		}

		// parse without scheme .e.g 8.8.8.8:53
		if !strings.Contains(server, "://") {
			if useRemote {
				server = "tcp://" + server
			} else {
				server = "udp://" + server
			}
		}

		u, err := url.Parse(server)
		if err != nil {
			return nil, fmt.Errorf("DNS NameServer[%d] format error: %s", idx, err.Error())
		}

		// parse with specific interface
		// .e.g 10.0.0.1#en0
		interfaceName := u.Fragment

		var addr, dnsNetType string
		switch u.Scheme {
		case "udp":
			addr, err = hostWithDefaultPort(u.Host, "53")
			dnsNetType = "" // UDP
		case "tcp":
			addr, err = hostWithDefaultPort(u.Host, "53")
			dnsNetType = "tcp" // TCP
		case "tls":
			addr, err = hostWithDefaultPort(u.Host, "853")
			dnsNetType = "tcp-tls" // DNS over TLS
		case "https":
			clearURL := url.URL{Scheme: "https", Host: u.Host, Path: u.Path}
			addr = clearURL.String()
			dnsNetType = "https" // DNS over HTTPS
		case "dhcp":
			addr = u.Host
			dnsNetType = "dhcp" // UDP from DHCP
		default:
			return nil, fmt.Errorf("DNS NameServer[%d] unsupport scheme: %s", idx, u.Scheme)
		}

		if err != nil {
			return nil, fmt.Errorf("DNS NameServer[%d] format error: %s", idx, err.Error())
		}

		nameservers = append(
			nameservers,
			dns.NameServer{
				Net:       dnsNetType,
				Addr:      addr,
				Interface: interfaceName,
				UseRemote: useRemote,
			},
		)
	}
	return nameservers, nil
}

func init() {
	dns.ParseNameServer = func(servers []string) ([]dns.NameServer, error) { // using by wireguard
		return parseNameServer(servers, false)
	}
}

func parseNameServerPolicy(nsPolicy map[string]string, useRemoteDnsDefault bool) (map[string]dns.NameServer, error) {
	policy := map[string]dns.NameServer{}

	for domain, server := range nsPolicy {
		nameservers, err := parseNameServer([]string{server}, useRemoteDnsDefault)
		if err != nil {
			return nil, err
		}
		if _, valid := trie.ValidAndSplitDomain(domain); !valid {
			return nil, fmt.Errorf("DNS ResoverRule invalid domain: %s", domain)
		}
		policy[domain] = nameservers[0]
	}

	return policy, nil
}

func parseFallbackIPCIDR(ips []string) ([]netip.Prefix, error) {
	ipNets := []netip.Prefix{}

	for idx, ip := range ips {
		ipnet, err := netip.ParsePrefix(ip)
		if err != nil {
			return nil, fmt.Errorf("DNS FallbackIP[%d] format error: %s", idx, err.Error())
		}
		ipNets = append(ipNets, ipnet)
	}

	return ipNets, nil
}

func parseDNS(rawCfg *RawConfig, hosts *trie.DomainTrie[netip.Addr]) (*DNS, error) {
	cfg := rawCfg.DNS
	if cfg.Enable && len(cfg.NameServer) == 0 {
		return nil, fmt.Errorf("if DNS configuration is turned on, NameServer cannot be empty")
	}

	dnsCfg := &DNS{
		Enable:       cfg.Enable,
		Listen:       cfg.Listen,
		IPv6:         cfg.IPv6,
		EnhancedMode: cfg.EnhancedMode,
		FallbackFilter: FallbackFilter{
			IPCIDR: []netip.Prefix{},
		},
	}
	var err error
	if dnsCfg.NameServer, err = parseNameServer(cfg.NameServer, rawCfg.UseRemoteDnsDefault); err != nil {
		return nil, err
	}

	if dnsCfg.Fallback, err = parseNameServer(cfg.Fallback, rawCfg.UseRemoteDnsDefault); err != nil {
		return nil, err
	}

	if dnsCfg.NameServerPolicy, err = parseNameServerPolicy(cfg.NameServerPolicy, rawCfg.UseRemoteDnsDefault); err != nil {
		return nil, err
	}

	if len(cfg.DefaultNameserver) == 0 {
		return nil, errors.New("default nameserver should have at least one nameserver")
	}
	if dnsCfg.DefaultNameserver, err = parseNameServer(cfg.DefaultNameserver, false); err != nil {
		return nil, err
	}
	// check default nameserver is pure ip addr
	for _, ns := range dnsCfg.DefaultNameserver {
		host, _, err := net.SplitHostPort(ns.Addr)
		if err != nil || net.ParseIP(host) == nil {
			return nil, errors.New("default nameserver should be pure IP")
		}
	}

	fakeIPRange, err := netip.ParsePrefix(cfg.FakeIPRange)
	T.SetFakeIPRange(fakeIPRange)
	if cfg.EnhancedMode == C.DNSFakeIP {
		if err != nil {
			return nil, err
		}

		var host *trie.DomainSet
		// fake ip skip host filter
		if len(cfg.FakeIPFilter) != 0 {
			// fake ip skip host filter
			tree := trie.New[struct{}]()
			for _, domain := range cfg.FakeIPFilter {
				tree.Insert(domain, struct{}{})
			}
			host = tree.NewDomainSet()
		}

		pool, err := fakeip.New(fakeip.Options{
			IPNet:       fakeIPRange,
			Size:        1000,
			Host:        host,
			Persistence: rawCfg.Profile.StoreFakeIP,
		})
		if err != nil {
			return nil, err
		}

		dnsCfg.FakeIPRange = pool
	}

	dnsCfg.FallbackFilter.GeoIP = cfg.FallbackFilter.GeoIP
	dnsCfg.FallbackFilter.GeoIPCode = cfg.FallbackFilter.GeoIPCode
	if fallbackip, err := parseFallbackIPCIDR(cfg.FallbackFilter.IPCIDR); err == nil {
		dnsCfg.FallbackFilter.IPCIDR = fallbackip
	}
	dnsCfg.FallbackFilter.Domain = cfg.FallbackFilter.Domain

	if cfg.UseHosts {
		dnsCfg.Hosts = hosts
	}

	if len(cfg.SearchDomains) != 0 {
		for _, domain := range cfg.SearchDomains {
			if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
				return nil, errors.New("search domains should not start or end with '.'")
			}
			if strings.Contains(domain, ":") {
				return nil, errors.New("search domains are for ipv4 only and should not contain ports")
			}
		}
		dnsCfg.SearchDomains = cfg.SearchDomains
	}

	return dnsCfg, nil
}

func parseAuthentication(rawRecords []string) []auth.AuthUser {
	users := []auth.AuthUser{}
	for _, line := range rawRecords {
		if user, pass, found := strings.Cut(line, ":"); found {
			users = append(users, auth.AuthUser{User: user, Pass: pass})
		}
	}
	return users
}

func parseSniffer(snifferRaw RawSniffer) (*Sniffer, error) {
	sniffer := &Sniffer{
		Enable:          snifferRaw.Enable,
		ForceDnsMapping: snifferRaw.ForceDnsMapping,
		ParsePureIp:     snifferRaw.ParsePureIp,
	}

	var ports []utils.Range[uint16]
	if len(snifferRaw.Ports) == 0 {
		ports = append(ports, *utils.NewRange[uint16](80, 80))
		ports = append(ports, *utils.NewRange[uint16](443, 443))
	} else {
		for _, portRange := range snifferRaw.Ports {
			portRaws := strings.Split(portRange, "-")
			p, err := strconv.ParseUint(portRaws[0], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("%s format error", portRange)
			}

			start := uint16(p)
			if len(portRaws) > 1 {
				p, err = strconv.ParseUint(portRaws[1], 10, 16)
				if err != nil {
					return nil, fmt.Errorf("%s format error", portRange)
				}

				end := uint16(p)
				ports = append(ports, *utils.NewRange(start, end))
			} else {
				ports = append(ports, *utils.NewRange(start, start))
			}
		}
	}

	sniffer.Ports = &ports

	loadSniffer := make(map[snifferTypes.Type]struct{})

	for _, snifferName := range snifferRaw.Sniffing {
		find := false
		for _, snifferType := range snifferTypes.List {
			if snifferType.String() == strings.ToUpper(snifferName) {
				find = true
				loadSniffer[snifferType] = struct{}{}
			}
		}

		if !find {
			return nil, fmt.Errorf("not find the sniffer[%s]", snifferName)
		}
	}

	for st := range loadSniffer {
		sniffer.Sniffers = append(sniffer.Sniffers, st)
	}

	forceDomainTrie := trie.New[struct{}]()
	for _, domain := range snifferRaw.ForceDomain {
		err := forceDomainTrie.Insert(domain, struct{}{})
		if err != nil {
			return nil, fmt.Errorf("error domian[%s] in force-domain, error:%v", domain, err)
		}
	}
	sniffer.ForceDomain = forceDomainTrie.NewDomainSet()

	skipDomainTrie := trie.New[struct{}]()
	for _, domain := range snifferRaw.SkipDomain {
		err := skipDomainTrie.Insert(domain, struct{}{})
		if err != nil {
			return nil, fmt.Errorf("error domian[%s] in force-domain, error:%v", domain, err)
		}
	}
	sniffer.SkipDomain = skipDomainTrie.NewDomainSet()

	return sniffer, nil
}
