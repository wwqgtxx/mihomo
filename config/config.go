package config

import (
	"encoding/json"
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
}

// Inbound
type Inbound struct {
	Port              int      `json:"port"`
	SocksPort         int      `json:"socks-port"`
	RedirPort         int      `json:"redir-port"`
	TProxyPort        int      `json:"tproxy-port"`
	MixedPort         int      `json:"mixed-port"`
	Tun               Tun      `json:"tun"`
	MixECConfig       string   `json:"mixec-config"`
	ShadowSocksConfig string   `json:"ss-config"`
	VmessConfig       string   `json:"vmess-config"`
	TcpTunConfig      string   `json:"tcptun-config"`
	UdpTunConfig      string   `json:"udptun-config"`
	MTProxyConfig     string   `json:"mtproxy-config"`
	Authentication    []string `json:"authentication"`
	AllowLan          bool     `json:"allow-lan"`
	BindAddress       string   `json:"bind-address"`
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
	Hosts             *trie.DomainTrie
	NameServerPolicy  map[string]dns.NameServer
}

// FallbackFilter config
type FallbackFilter struct {
	GeoIP     bool         `yaml:"geoip"`
	GeoIPCode string       `yaml:"geoip-code"`
	IPCIDR    []*net.IPNet `yaml:"ipcidr"`
	Domain    []string     `yaml:"domain"`
}

// Profile config
type Profile struct {
	StoreSelected bool `yaml:"store-selected"`
	StoreFakeIP   bool `yaml:"store-fake-ip"`
}

// Tun config
type Tun struct {
	Enable              bool     `yaml:"enable" json:"enable"`
	Stack               string   `yaml:"stack" json:"stack"`
	DNSHijack           []string `yaml:"dns-hijack" json:"dns-hijack"`
	AutoDetectInterface bool     `yaml:"auto-detect-interface" json:"auto-detect-interface"`
	AutoRoute           bool     `yaml:"auto-route" json:"auto-route"`

	InterfaceName          string         `yaml:"interface-name" json:"interface_name,omitempty"`
	MTU                    uint32         `yaml:"mtu" json:"mtu,omitempty"`
	Inet4Address           []ListenPrefix `yaml:"inet4-address" json:"inet4_address,omitempty"`
	Inet6Address           []ListenPrefix `yaml:"inet6-address" json:"inet6_address,omitempty"`
	StrictRoute            bool           `yaml:"strict-route" json:"strict_route,omitempty"`
	Inet4RouteAddress      []ListenPrefix `yaml:"inet4_route_address" json:"inet4_route_address,omitempty"`
	Inet6RouteAddress      []ListenPrefix `yaml:"inet6_route_address" json:"inet6_route_address,omitempty"`
	IncludeUID             []uint32       `yaml:"include-uid" json:"include_uid,omitempty"`
	IncludeUIDRange        []string       `yaml:"include-uid-range" json:"include_uid_range,omitempty"`
	ExcludeUID             []uint32       `yaml:"exclude-uid" json:"exclude_uid,omitempty"`
	ExcludeUIDRange        []string       `yaml:"exclude-uid-range" json:"exclude_uid_range,omitempty"`
	IncludeAndroidUser     []int          `yaml:"include-android-user" json:"include_android_user,omitempty"`
	IncludePackage         []string       `yaml:"include-package" json:"include_package,omitempty"`
	ExcludePackage         []string       `yaml:"exclude-package" json:"exclude_package,omitempty"`
	EndpointIndependentNat bool           `yaml:"endpoint-independent-nat" json:"endpoint_independent_nat,omitempty"`
	UDPTimeout             int64          `yaml:"udp-timeout" json:"udp_timeout,omitempty"`
}

func (t Tun) String() string {
	b, _ := json.Marshal(t)
	return string(b)
}

type ListenPrefix netip.Prefix

func (p ListenPrefix) MarshalJSON() ([]byte, error) {
	prefix := netip.Prefix(p)
	if !prefix.IsValid() {
		return json.Marshal(nil)
	}
	return json.Marshal(prefix.String())
}

func (p ListenPrefix) MarshalYAML() (interface{}, error) {
	prefix := netip.Prefix(p)
	if !prefix.IsValid() {
		return nil, nil
	}
	return prefix.String(), nil
}

func (p *ListenPrefix) UnmarshalJSON(bytes []byte) error {
	var value string
	err := json.Unmarshal(bytes, &value)
	if err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return err
	}
	*p = ListenPrefix(prefix)
	return nil
}

func (p *ListenPrefix) UnmarshalYAML(node *yaml.Node) error {
	var value string
	err := node.Decode(&value)
	if err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return err
	}
	*p = ListenPrefix(prefix)
	return nil
}

func (p ListenPrefix) Build() netip.Prefix {
	return netip.Prefix(p)
}

type Sniffer struct {
	Enable          bool
	Sniffers        []sniffer.Type
	Reverses        *trie.DomainTrie
	ForceDomain     *trie.DomainTrie
	SkipDomain      *trie.DomainTrie
	Ports           *[]utils.Range[uint16]
	ForceDnsMapping bool
	ParsePureIp     bool
}

// Experimental config
type Experimental struct{}

// Config is clash config manager
type Config struct {
	General        *General
	DNS            *DNS
	Experimental   *Experimental
	Hosts          *trie.DomainTrie
	Profile        *Profile
	Rules          []C.Rule
	RulesProviders map[string]R.RuleProvider
	Users          []auth.AuthUser
	Proxies        map[string]C.Proxy
	Providers      map[string]providerTypes.ProxyProvider
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
	TcpTunConfig           string       `yaml:"tcptun-config"`
	UdpTunConfig           string       `yaml:"udptun-config"`
	MTProxyConfig          string       `yaml:"mtproxy-config"`
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
	Tun           Tun                       `yaml:"tun"`
	Experimental  Experimental              `yaml:"experimental"`
	Profile       Profile                   `yaml:"profile"`
	Proxy         []map[string]any          `yaml:"proxies"`
	ProxyGroup    []map[string]any          `yaml:"proxy-groups"`
	Rule          []string                  `yaml:"rules"`
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
		Tun: Tun{
			Enable:              false,
			Stack:               "system",
			DNSHijack:           []string{},
			AutoDetectInterface: true,
			AutoRoute:           true,
			Inet4Address:        []ListenPrefix{ListenPrefix(netip.MustParsePrefix("198.18.0.1/30"))},
			Inet6Address:        []ListenPrefix{ListenPrefix(netip.MustParsePrefix("fdfe:dcba:9876::1/126"))},
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
				"223.5.5.5",
				"8.8.8.8",
				"1.0.0.1",
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

	rules, ruleProviders, err := parseRules(rawCfg, proxies)
	if err != nil {
		return nil, err
	}
	config.Rules = rules
	config.RulesProviders = ruleProviders

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
			MixECConfig:       cfg.MixECConfig,
			ShadowSocksConfig: cfg.ShadowSocksConfig,
			VmessConfig:       cfg.VmessConfig,
			TcpTunConfig:      cfg.TcpTunConfig,
			UdpTunConfig:      cfg.UdpTunConfig,
			MTProxyConfig:     cfg.MTProxyConfig,
			AllowLan:          cfg.AllowLan,
			BindAddress:       cfg.BindAddress,
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

	proxies["DIRECT"] = adapter.NewProxy(outbound.NewDirect())
	proxies["REJECT"] = adapter.NewProxy(outbound.NewReject())
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

		pd, err := provider.ParseProxyProvider(name, mapping, healthCheckLazyDefault)
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
		ps = append(ps, proxies[v])
	}
	hc := provider.NewHealthCheck(ps, "", 0, true, provider.ReservedName)
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

func parseRules(cfg *RawConfig, proxies map[string]C.Proxy) (rules []C.Rule, providersMap map[string]R.RuleProvider, err error) {
	rulesConfig := cfg.Rule
	providersMap = make(map[string]R.RuleProvider)
	providersConfig := cfg.RuleProviders

	// parse and initial providers
	for name, mapping := range providersConfig {
		rd, err := R.ParseRuleProvider(name, mapping)
		if err != nil {
			return nil, nil, fmt.Errorf("parse rule ruleProvider %s error: %w", name, err)
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

	// parse rules
	for idx, line := range rulesConfig {
		rule := trimArr(strings.Split(line, ","))
		var (
			payload string
			target  string
			params  = []string{}
		)

		ruleName := rule[0]
		if ruleName == "NOT" || ruleName == "OR" || ruleName == "AND" {
			payload = strings.Join(rule[1:len(rule)-1], ",")
			target = rule[len(rule)-1]
		} else {
			switch l := len(rule); {
			case l == 2:
				target = rule[1]
			case l == 3:
				payload = rule[1]
				target = rule[2]
			case l >= 4:
				payload = rule[1]
				target = rule[2]
				params = rule[3:]
			default:
				return nil, nil, fmt.Errorf("rules[%d] [%s] error: format invalid", idx, line)
			}
		}

		if _, ok := proxies[target]; !ok {
			return nil, nil, fmt.Errorf("rules[%d] [%s] error: proxy [%s] not found", idx, line, target)
		}

		rule = trimArr(rule)
		params = trimArr(params)

		parsed, parseErr := R.ParseRule(rule[0], payload, target, params)
		if parseErr != nil {
			return nil, nil, fmt.Errorf("rules[%d] [%s] error: %s", idx, line, parseErr.Error())
		}

		rules = append(rules, parsed)
	}

	return rules, providersMap, nil
}

func parseHosts(cfg *RawConfig) (*trie.DomainTrie, error) {
	tree := trie.New()

	// add default hosts
	if err := tree.Insert("localhost", net.IP{127, 0, 0, 1}); err != nil {
		log.Errorln("insert localhost to host error: %s", err.Error())
	}

	if len(cfg.Hosts) != 0 {
		for domain, ipStr := range cfg.Hosts {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return nil, fmt.Errorf("%s is not a valid IP", ipStr)
			}
			tree.Insert(domain, ip)
		}
	}

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

func parseFallbackIPCIDR(ips []string) ([]*net.IPNet, error) {
	ipNets := []*net.IPNet{}

	for idx, ip := range ips {
		_, ipnet, err := net.ParseCIDR(ip)
		if err != nil {
			return nil, fmt.Errorf("DNS FallbackIP[%d] format error: %s", idx, err.Error())
		}
		ipNets = append(ipNets, ipnet)
	}

	return ipNets, nil
}

func parseDNS(rawCfg *RawConfig, hosts *trie.DomainTrie) (*DNS, error) {
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
			IPCIDR: []*net.IPNet{},
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

	if cfg.EnhancedMode == C.DNSFakeIP {
		_, ipnet, err := net.ParseCIDR(cfg.FakeIPRange)
		if err != nil {
			return nil, err
		}

		var host *trie.DomainTrie
		// fake ip skip host filter
		if len(cfg.FakeIPFilter) != 0 {
			host = trie.New()
			for _, domain := range cfg.FakeIPFilter {
				host.Insert(domain, true)
			}
		}

		pool, err := fakeip.New(fakeip.Options{
			IPNet:       ipnet,
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
	sniffer.ForceDomain = trie.New()
	for _, domain := range snifferRaw.ForceDomain {
		err := sniffer.ForceDomain.Insert(domain, true)
		if err != nil {
			return nil, fmt.Errorf("error domian[%s] in force-domain, error:%v", domain, err)
		}
	}

	sniffer.SkipDomain = trie.New()
	for _, domain := range snifferRaw.SkipDomain {
		err := sniffer.SkipDomain.Insert(domain, true)
		if err != nil {
			return nil, fmt.Errorf("error domian[%s] in force-domain, error:%v", domain, err)
		}
	}

	return sniffer, nil
}
