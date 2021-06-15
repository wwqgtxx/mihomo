package tunnel

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/adapter/provider"
	"github.com/Dreamacro/clash/component/nat"
	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/tunnel/statistic"

	"github.com/eapache/queue"
)

var (
	tcpQueueIn     = make(chan C.ConnContext)
	udpQueueIn     = make(chan *inbound.PacketAdapter)
	tcpQueueOut    = make(chan C.ConnContext)
	udpQueueOut    = make(chan *inbound.PacketAdapter)
	tcpQueueBuffer = queue.New()
	udpQueueBuffer = queue.New()
	natTable       = nat.New()
	rules          []C.Rule
	proxies        = make(map[string]C.Proxy)
	providers      map[string]provider.ProxyProvider
	configMux      sync.RWMutex

	// Outbound Rule
	mode = Rule

	// default timeout for UDP session
	udpTimeout = 60 * time.Second
)

func init() {
	go process()
	go func() {
		var input, output chan C.ConnContext
		var next C.ConnContext
		input = tcpQueueIn

		for input != nil || output != nil {
			select {
			case elem, open := <-input:
				if open {
					tcpQueueBuffer.Add(elem)
				} else {
					input = nil
				}
			case output <- next:
				tcpQueueBuffer.Remove()
			}

			if tcpQueueBuffer.Length() > 0 {
				output = tcpQueueOut
				next = tcpQueueBuffer.Peek().(C.ConnContext)
			} else {
				output = nil
				next = nil
			}
		}

		close(tcpQueueOut)
	}()
	go func() {
		var input, output chan *inbound.PacketAdapter
		var next *inbound.PacketAdapter
		input = udpQueueIn

		for input != nil || output != nil {
			select {
			case elem, open := <-input:
				if open {
					udpQueueBuffer.Add(elem)
				} else {
					input = nil
				}
			case output <- next:
				udpQueueBuffer.Remove()
			}

			if udpQueueBuffer.Length() > 0 {
				output = udpQueueOut
				next = udpQueueBuffer.Peek().(*inbound.PacketAdapter)
			} else {
				output = nil
				next = nil
			}
		}

		close(tcpQueueOut)
	}()
}

// TCPIn return fan-in queue
func TCPIn() chan<- C.ConnContext {
	return tcpQueueIn
}

// UDPIn return fan-in udp queue
func UDPIn() chan<- *inbound.PacketAdapter {
	return udpQueueIn
}

// Rules return all rules
func Rules() []C.Rule {
	return rules
}

// UpdateRules handle update rules
func UpdateRules(newRules []C.Rule) {
	configMux.Lock()
	rules = newRules
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
	queue := udpQueueOut
	for conn := range queue {
		handleUDPConn(conn)
	}
}

func process() {
	numUDPWorkers := 4
	if runtime.NumCPU() > numUDPWorkers {
		numUDPWorkers = runtime.NumCPU()
	}
	for i := 0; i < numUDPWorkers; i++ {
		go processUDP()
	}

	queue := tcpQueueOut
	for conn := range queue {
		go handleTCPConn(conn)
	}
}

func needLookupIP(metadata *C.Metadata) bool {
	return resolver.MappingEnabled() && metadata.Host == "" && metadata.DstIP != nil
}

func preHandleMetadata(metadata *C.Metadata) error {
	// handle IP string on host
	if ip := net.ParseIP(metadata.Host); ip != nil {
		metadata.DstIP = ip
		metadata.Host = ""
		if ip.To4() != nil {
			metadata.AddrType = C.AtypIPv4
		} else {
			metadata.AddrType = C.AtypIPv6
		}
	}

	// preprocess enhanced-mode metadata
	if needLookupIP(metadata) {
		host, exist := resolver.FindHostByIP(metadata.DstIP)
		if exist {
			metadata.Host = host
			metadata.AddrType = C.AtypDomainName
			if resolver.FakeIPEnabled() {
				metadata.DstIP = nil
			} else if node := resolver.DefaultHosts.Search(host); node != nil {
				// redir-host should lookup the hosts
				metadata.DstIP = node.Data.(net.IP)
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
	var fAddr net.Addr
	if resolver.IsExistFakeIP(metadata.DstIP) {
		fAddr = metadata.UDPAddr()
	}

	if err := preHandleMetadata(metadata); err != nil {
		log.Debugln("[Metadata PreHandle] error: %s", err)
		return
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

		ctx := context.NewPacketConnContext(metadata)
		proxy, rule, err := resolveMetadata(ctx, metadata)
		if err != nil {
			log.Warnln("[UDP] Parse metadata failed: %s", err.Error())
			return
		}

		rawPc, err := proxy.DialUDP(metadata)
		if err != nil {
			if rule == nil {
				log.Warnln("[%s][UDP] dial %s to %s error: %s", metadata.Type.String(), proxy.Name(), metadata.String(), err.Error())
			} else {
				log.Warnln("[%s][UDP] dial %s (match %s/%s) to %s error: %s", metadata.Type.String(), proxy.Name(), rule.RuleType().String(), rule.Payload(), metadata.String(), err.Error())
			}
			return
		}
		ctx.InjectPacketConn(rawPc)
		pc := statistic.NewUDPTracker(rawPc, statistic.DefaultManager, metadata, rule)

		switch true {
		case rule != nil:
			log.Infoln("[%s][UDP] %s --> %v match %s(%s) using %s", metadata.Type.String(), metadata.SourceAddress(), metadata.String(), rule.RuleType().String(), rule.Payload(), rawPc.Chains().String())
		case mode == Global:
			log.Infoln("[%s][UDP] %s --> %v using GLOBAL", metadata.Type.String(), metadata.SourceAddress(), metadata.String())
		case mode == Direct:
			log.Infoln("[%s][UDP] %s --> %v using DIRECT", metadata.Type.String(), metadata.SourceAddress(), metadata.String())
		default:
			log.Infoln("[%s][UDP] %s --> %v doesn't match any rule using DIRECT", metadata.Type.String(), metadata.SourceAddress(), metadata.String())
		}

		go handleUDPToLocal(packet.UDPPacket, pc, key, fAddr)

		natTable.Set(key, pc)
		handle()
	}()
}

func handleTCPConn(ctx C.ConnContext) {
	defer ctx.Conn().Close()

	metadata := ctx.Metadata()
	if !metadata.Valid() {
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}

	if err := preHandleMetadata(metadata); err != nil {
		log.Debugln("[Metadata PreHandle] error: %s", err)
		return
	}

	proxy, rule, err := resolveMetadata(ctx, metadata)
	if err != nil {
		log.Warnln("[Metadata] parse failed: %s", err.Error())
		return
	}

	remoteConn, err := proxy.Dial(metadata)
	if err != nil {
		if rule == nil {
			log.Warnln("[%s][TCP] dial %s to %s error: %s", metadata.Type.String(), proxy.Name(), metadata.String(), err.Error())
		} else {
			log.Warnln("[%s][TCP] dial %s (match %s/%s) to %s error: %s", metadata.Type.String(), proxy.Name(), rule.RuleType().String(), rule.Payload(), metadata.String(), err.Error())
		}
		return
	}
	remoteConn = statistic.NewTCPTracker(remoteConn, statistic.DefaultManager, metadata, rule)
	defer remoteConn.Close()

	switch true {
	case rule != nil:
		log.Infoln("[%s][TCP] %s --> %v match %s(%s) using %s", metadata.Type.String(), metadata.SourceAddress(), metadata.String(), rule.RuleType().String(), rule.Payload(), remoteConn.Chains().String())
	case mode == Global:
		log.Infoln("[%s][TCP] %s --> %v using GLOBAL", metadata.Type.String(), metadata.SourceAddress(), metadata.String())
	case mode == Direct:
		log.Infoln("[%s][TCP] %s --> %v using DIRECT", metadata.Type.String(), metadata.SourceAddress(), metadata.String())
	default:
		log.Infoln("[%s][TCP] %s --> %v doesn't match any rule using DIRECT", metadata.Type.String(), metadata.SourceAddress(), metadata.String())
	}

	switch c := ctx.(type) {
	case *context.HTTPContext:
		handleHTTP(c, remoteConn)
	default:
		handleSocket(ctx, remoteConn)
	}
}

func shouldResolveIP(rule C.Rule, metadata *C.Metadata) bool {
	return rule.ShouldResolveIP() && metadata.Host != "" && metadata.DstIP == nil
}

func match(metadata *C.Metadata) (C.Proxy, C.Rule, error) {
	configMux.RLock()
	defer configMux.RUnlock()

	var resolved bool

	if node := resolver.DefaultHosts.Search(metadata.Host); node != nil {
		ip := node.Data.(net.IP)
		metadata.DstIP = ip
		resolved = true
	}

	for _, rule := range rules {
		if !resolved && shouldResolveIP(rule, metadata) {
			ip, err := resolver.ResolveIP(metadata.Host)
			if err != nil {
				log.Debugln("[DNS] resolve %s error: %s", metadata.Host, err.Error())
			} else {
				log.Debugln("[DNS] %s --> %s", metadata.Host, ip.String())
				metadata.DstIP = ip
			}
			resolved = true
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
