package tunnel

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/jpillora/backoff"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/common/channel"
	"github.com/Dreamacro/clash/component/inner_dialer"
	"github.com/Dreamacro/clash/component/mmdb"
	"github.com/Dreamacro/clash/component/nat"
	P "github.com/Dreamacro/clash/component/process"
	"github.com/Dreamacro/clash/component/resolver"
	"github.com/Dreamacro/clash/component/sniffer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/constant/provider"
	icontext "github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/log"
	R "github.com/Dreamacro/clash/rule"
	"github.com/Dreamacro/clash/tunnel/statistic"
)

var (
	tcpQueue       = channel.NewInfiniteChannel[C.ConnContext]()
	udpQueue       = channel.NewInfiniteChannel[*inbound.PacketAdapter]()
	natTable       = nat.New()
	rules          []C.Rule
	ruleProviders  map[string]R.RuleProvider
	proxies        = make(map[string]C.Proxy)
	providers      map[string]provider.ProxyProvider
	sniffingEnable bool
	configMux      sync.RWMutex

	// Outbound Rule
	mode = Rule

	// default timeout for UDP session
	udpTimeout = 60 * time.Second

	preResolveProcessName = false
)

func SetSniffing(b bool) {
	if sniffer.Dispatcher.Enable() {
		configMux.Lock()
		sniffingEnable = b
		configMux.Unlock()
	}
}

func UpdateSniffer(dispatcher *sniffer.SnifferDispatcher) {
	configMux.Lock()
	sniffer.Dispatcher = dispatcher
	sniffingEnable = true
	configMux.Unlock()
}

func IsSniffing() bool {
	return sniffingEnable
}

func PreResolveProcessName() bool {
	return preResolveProcessName
}

func SetPreResolveProcessName(b bool) {
	preResolveProcessName = b
}

func init() {
	inner_dialer.Init(TCPIn(), UDPIn())
	go process()
}

// TCPIn return fan-in queue
func TCPIn() chan<- C.ConnContext {
	return tcpQueue.In()
}

// UDPIn return fan-in udp queue
func UDPIn() chan<- *inbound.PacketAdapter {
	return udpQueue.In()
}

// Rules return all rules
func Rules() []C.Rule {
	return rules
}

// RuleProviders return all compatible providers
func RuleProviders() map[string]R.RuleProvider {
	return ruleProviders
}

// UpdateRules handle update rules
func UpdateRules(newRules []C.Rule, newProviders map[string]R.RuleProvider) {
	configMux.Lock()
	rules = newRules
	ruleProviders = newProviders
	configMux.Unlock()
}

// Proxies return all proxies
func Proxies() map[string]C.Proxy {
	return proxies
}

// Providers return all compatible providers
func Providers() map[string]provider.ProxyProvider {
	return providers
}

// UpdateProxies handle update proxies
func UpdateProxies(newProxies map[string]C.Proxy, newProviders map[string]provider.ProxyProvider) {
	configMux.Lock()
	proxies = newProxies
	providers = newProviders
	configMux.Unlock()
}

// Mode return current mode
func Mode() TunnelMode {
	return mode
}

// SetMode change the mode of tunnel
func SetMode(m TunnelMode) {
	mode = m
}

// processUDP starts a loop to handle udp packet
func processUDP() {
	queue := udpQueue.Out()
	for conn := range queue {
		handleUDPConn(conn)
	}
}

func process() {
	numUDPWorkers := 4
	if num := runtime.GOMAXPROCS(0); num > numUDPWorkers {
		numUDPWorkers = num
	}
	for i := 0; i < numUDPWorkers; i++ {
		go processUDP()
	}

	queue := tcpQueue.Out()
	for conn := range queue {
		go handleTCPConn(conn)
	}
}

func needLookupIP(metadata *C.Metadata) bool {
	return resolver.MappingEnabled() && metadata.Host == "" && metadata.DstIP.IsValid()
}

func preHandleMetadata(metadata *C.Metadata) error {
	// handle IP string on host
	if ip, err := netip.ParseAddr(metadata.Host); err == nil {
		metadata.DstIP = ip
		metadata.Host = ""
	}

	// preprocess enhanced-mode metadata
	if needLookupIP(metadata) {
		host, exist := resolver.FindHostByIP(metadata.DstIP)
		if exist {
			metadata.Host = host
			metadata.DNSMode = C.DNSMapping
			if resolver.FakeIPEnabled() {
				metadata.DstIP = netip.Addr{}
				metadata.DNSMode = C.DNSFakeIP
			} else if node := resolver.DefaultHosts.Search(host); node != nil {
				// redir-host should lookup the hosts
				metadata.DstIP = node.Data()
			}
		} else if resolver.IsFakeIP(metadata.DstIP) {
			return fmt.Errorf("fake DNS record %s missing", metadata.DstIP)
		}
	}

	return nil
}

func resolveMetadata(ctx C.PlainContext, metadata *C.Metadata) (proxy C.Proxy, rule C.Rule, err error) {
	switch mode {
	case Direct:
		proxy = proxies["DIRECT"]
	case Global:
		proxy = proxies["GLOBAL"]
	// Rule
	default:
		proxy, rule, err = match(metadata)
	}
	return
}

func handleUDPConn(packet *inbound.PacketAdapter) {
	metadata := packet.Metadata()
	if !metadata.Valid() {
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}

	// make a fAddr if request ip is fakeip
	var fAddr netip.Addr
	if resolver.IsExistFakeIP(metadata.DstIP) {
		fAddr = metadata.DstIP
		fAddr = fAddr.Unmap()
	}

	if err := preHandleMetadata(metadata); err != nil {
		log.Debugln("[Metadata PreHandle] error: %s", err)
		return
	}

	// local resolve UDP dns
	if !metadata.Resolved() {
		ips, err := resolver.LookupIPWithResolver(context.Background(), metadata.Host, resolver.DialerResolver)
		if err != nil {
			return
		} else if len(ips) == 0 {
			return
		}
		metadata.DstIP = ips[0]
	}

	key := packet.LocalAddr().String()

	handle := func() bool {
		pc := natTable.Get(key)
		if pc != nil {
			handleUDPToRemote(packet, pc, metadata)
			return true
		}
		return false
	}

	if handle() {
		return
	}

	lockKey := key + "-lock"
	cond, loaded := natTable.GetOrCreateLock(lockKey)

	go func() {
		if loaded {
			cond.L.Lock()
			cond.Wait()
			handle()
			cond.L.Unlock()
			return
		}

		defer func() {
			natTable.Delete(lockKey)
			cond.Broadcast()
		}()

		pCtx := icontext.NewPacketConnContext(metadata)
		proxy, rule, err := resolveMetadata(pCtx, metadata)
		if err != nil {
			log.Warnln("[UDP] Parse metadata failed: %s", err.Error())
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), C.DefaultUDPTimeout)
		defer cancel()
		rawPc, err := retry(ctx, func(ctx context.Context) (C.PacketConn, error) {
			return proxy.ListenPacketContext(ctx, metadata.Pure())
		}, func(err error) {
			if rule == nil {
				log.Warnln(
					"[%s][UDP] dial %s(%s) %s --> %s error: %s",
					metadata.Type.String(),
					proxy.Name(),
					metadata.Process,
					metadata.SourceAddress(),
					metadata.RemoteAddress(),
					err.Error(),
				)
			} else {
				log.Warnln("[%s][UDP] dial %s(%s) (match %s/%s) %s --> %s error: %s", metadata.Type.String(), proxy.Name(), metadata.Process, rule.RuleType().String(), rule.Payload(), metadata.SourceAddress(), metadata.RemoteAddress(), err.Error())
			}
		})
		if err != nil {
			return
		}
		pCtx.InjectPacketConn(rawPc)
		pc := statistic.NewUDPTracker(rawPc, statistic.DefaultManager, metadata, rule)

		switch true {
		case rule != nil:
			log.Infoln(
				"[%s][UDP] %s(%s) --> %s match %s(%s) using %s",
				metadata.Type.String(),
				metadata.SourceAddress(),
				metadata.Process,
				metadata.RemoteAddress(),
				rule.RuleType().String(),
				rule.Payload(),
				rawPc.Chains().String(),
			)
		case mode == Global:
			log.Infoln("[%s][UDP] %s(%s) --> %s using GLOBAL", metadata.Type.String(), metadata.SourceAddress(), metadata.Process, metadata.RemoteAddress())
		case mode == Direct:
			log.Infoln("[%s][UDP] %s(%s) --> %s using DIRECT", metadata.Type.String(), metadata.SourceAddress(), metadata.Process, metadata.RemoteAddress())
		default:
			log.Infoln(
				"[%s][UDP] %s(%s) --> %s doesn't match any rule using DIRECT",
				metadata.Type.String(),
				metadata.SourceAddress(),
				metadata.Process,
				metadata.RemoteAddress(),
			)
		}

		oAddr := metadata.DstIP
		oAddr = oAddr.Unmap()
		go handleUDPToLocal(packet.UDPPacket, pc, key, oAddr, fAddr)

		natTable.Set(key, pc)
		handle()
	}()
}

func handleTCPConn(connCtx C.ConnContext) {
	defer connCtx.Conn().Close()

	metadata := connCtx.Metadata()
	if !metadata.Valid() {
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}

	if err := preHandleMetadata(metadata); err != nil {
		log.Debugln("[Metadata PreHandle] error: %s", err)
		return
	}

	if sniffer.Dispatcher.Enable() && sniffingEnable {
		sniffer.Dispatcher.TCPSniff(connCtx.Conn(), metadata)
	}

	proxy, rule, err := resolveMetadata(connCtx, metadata)
	if err != nil {
		log.Warnln("[Metadata] parse failed: %s", err.Error())
		return
	}

	dialMetadata := metadata
	if len(metadata.Host) > 0 {
		if node := resolver.DefaultHosts.Search(metadata.Host); node != nil {
			dialMetadata.DstIP = node.Data()
			dialMetadata.DNSMode = C.DNSHosts
			dialMetadata = dialMetadata.Pure()
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTCPTimeout)
	defer cancel()
	remoteConn, err := retry(ctx, func(ctx context.Context) (C.Conn, error) {
		return proxy.DialContext(ctx, dialMetadata)
	}, func(err error) {
		if rule == nil {
			log.Warnln(
				"[%s][TCP] dial %s(%s) %s --> %s error: %s",
				metadata.Type.String(),
				proxy.Name(),
				metadata.Process,
				metadata.SourceAddress(),
				metadata.RemoteAddress(),
				err.Error(),
			)
		} else {
			log.Warnln("[%s][TCP] dial %s(%s) (match %s/%s) %s --> %s error: %s", metadata.Type.String(), proxy.Name(), metadata.Process, rule.RuleType().String(), rule.Payload(), metadata.SourceAddress(), metadata.RemoteAddress(), err.Error())
		}
	})
	if err != nil {
		return
	}
	remoteConn = statistic.NewTCPTracker(remoteConn, statistic.DefaultManager, metadata, rule)
	defer remoteConn.Close()

	switch true {
	case rule != nil:
		log.Infoln(
			"[%s][TCP] %s(%s) --> %s match %s(%s) using %s",
			metadata.Type.String(),
			metadata.SourceAddress(),
			metadata.Process,
			metadata.RemoteAddress(),
			rule.RuleType().String(),
			rule.Payload(),
			remoteConn.Chains().String(),
		)
	case mode == Global:
		log.Infoln("[%s][TCP] %s(%s) --> %s using GLOBAL", metadata.Type.String(), metadata.SourceAddress(), metadata.Process, metadata.RemoteAddress())
	case mode == Direct:
		log.Infoln("[%s][TCP] %s(%s) --> %s using DIRECT", metadata.Type.String(), metadata.SourceAddress(), metadata.Process, metadata.RemoteAddress())
	default:
		log.Infoln(
			"[%s][TCP] %s(%s) --> %s doesn't match any rule using DIRECT",
			metadata.Type.String(),
			metadata.SourceAddress(),
			metadata.Process,
			metadata.RemoteAddress(),
		)
	}

	handleSocket(connCtx, remoteConn)
}

func shouldResolveIP(rule C.Rule, metadata *C.Metadata) bool {
	return rule.ShouldResolveIP() && metadata.Host != "" && !metadata.DstIP.IsValid()
}

func match(metadata *C.Metadata) (C.Proxy, C.Rule, error) {
	configMux.RLock()
	defer configMux.RUnlock()

	var resolved bool
	var processFound bool

	if node := resolver.DefaultHosts.Search(metadata.Host); node != nil {
		metadata.DstIP = node.Data()
		resolved = true
	}

	checkResolved := func(rule C.Rule) {
		if !resolved && shouldResolveIP(rule, metadata) {
			ip, err := resolver.ResolveIP(metadata.Host)
			if err != nil {
				log.Infoln("[DNS] resolve %s error: %s", metadata.Host, err.Error())
			} else {
				record, _ := mmdb.Instance().Country(ip.AsSlice())
				if len(record.Country.IsoCode) > 0 {
					log.Infoln("[DNS] %s --> %s [GEO=%s]", metadata.Host, ip.String(), record.Country.IsoCode)
				} else {
					log.Infoln("[DNS] %s --> %s", metadata.Host, ip.String())
				}

				metadata.DstIP = ip
			}
			resolved = true
		}
	}

	for _, rule := range rules {
		if rule.RuleType() == C.RuleSet {
			ruleProvider, ok := ruleProviders[rule.Payload()]
			if !ok {
				log.Warnln("%s RuleProvider is not exists", rule.Payload())
				continue
			}
			adapter, ok := proxies[rule.Adapter()]
			if !ok {
				continue
			}
			if metadata.NetWork == C.UDP && !adapter.SupportUDP() {
				continue
			}

			for _, subRule := range ruleProvider.Rules() {
				checkResolved(subRule)
				if subRule.Match(metadata) {
					return adapter, rule, nil
				}
			}
			continue
		}

		checkResolved(rule)

		if !processFound && (rule.ShouldFindProcess() || preResolveProcessName) {
			processFound = true

			srcPort, err := strconv.ParseUint(metadata.SrcPort, 10, 16)
			if err == nil {
				path, err := P.FindProcessName(metadata.NetWork.String(), metadata.SrcIP, int(srcPort))
				if err != nil {
					log.Debugln("[Process] find process %s: %v", metadata.String(), err)
				} else {
					log.Debugln("[Process] %s from process %s", metadata.String(), path)
					metadata.ProcessPath = path
					metadata.Process = filepath.Base(path)
				}
			}
		}

		if rule.Match(metadata) {
			adapter, ok := proxies[rule.Adapter()]
			if !ok {
				continue
			}

			if metadata.NetWork == C.UDP && !adapter.SupportUDP() {
				log.Debugln("%s UDP is not supported", adapter.Name())
				continue
			}
			return adapter, rule, nil
		}
	}

	return proxies["DIRECT"], nil, nil
}

func retry[T any](ctx context.Context, ft func(context.Context) (T, error), fe func(err error)) (t T, err error) {
	b := &backoff.Backoff{
		Min:    10 * time.Millisecond,
		Max:    1 * time.Second,
		Factor: 2,
		Jitter: true,
	}
	for i := 0; i < 10; i++ {
		t, err = ft(ctx)
		if err != nil {
			if fe != nil {
				fe(err)
			}
			select {
			case <-time.After(b.Duration()):
				continue
			case <-ctx.Done():
				return
			}
		} else {
			break
		}
	}
	return
}
