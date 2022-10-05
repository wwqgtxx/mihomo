package sing_tun

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/iface"
	"github.com/Dreamacro/clash/component/resolver"
	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/dns"
	"github.com/Dreamacro/clash/listener/sing"
	"github.com/Dreamacro/clash/log"

	D "github.com/miekg/dns"

	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/ranges"
)

type Listener struct {
	closed  bool
	options config.Tun
	handler tun.Handler

	tunIf    tun.Tun
	tunStack tun.Stack

	networkUpdateMonitor    tun.NetworkUpdateMonitor
	defaultInterfaceMonitor tun.DefaultInterfaceMonitor
}

func New(options config.Tun, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) (*Listener, error) {
	tunName := options.InterfaceName
	if tunName == "" {
		tunName = tun.CalculateInterfaceName("clashr-tun")
	}
	tunMTU := options.MTU
	if tunMTU == 0 {
		tunMTU = 9000
	}
	var udpTimeout int64
	if options.UDPTimeout != 0 {
		udpTimeout = options.UDPTimeout
	} else {
		udpTimeout = int64(C.DefaultUDPTimeout.Seconds())
	}
	includeUID := uidToRange(options.IncludeUID)
	if len(options.IncludeUIDRange) > 0 {
		var err error
		includeUID, err = parseRange(includeUID, options.IncludeUIDRange)
		if err != nil {
			return nil, E.Cause(err, "parse include_uid_range")
		}
	}
	excludeUID := uidToRange(options.ExcludeUID)
	if len(options.ExcludeUIDRange) > 0 {
		var err error
		excludeUID, err = parseRange(excludeUID, options.ExcludeUIDRange)
		if err != nil {
			return nil, E.Cause(err, "parse exclude_uid_range")
		}
	}

	var dnsHijack []netip.AddrPort

	for _, d := range options.DnsHijack {
		if _, after, ok := strings.Cut(d, "://"); ok {
			d = after
		}
		d = strings.Replace(d, "any", "0.0.0.0", 1)
		addrPort, err := netip.ParseAddrPort(d)
		if err != nil {
			return nil, fmt.Errorf("parse dns-hijack url error: %w", err)
		}

		dnsHijack = append(dnsHijack, addrPort)
	}
	for _, a := range options.Inet4Address {
		addrPort := netip.AddrPortFrom(a.Build().Addr().Next(), 53)
		dnsHijack = append(dnsHijack, addrPort)
	}
	for _, a := range options.Inet6Address {
		addrPort := netip.AddrPortFrom(a.Build().Addr().Next(), 53)
		dnsHijack = append(dnsHijack, addrPort)
	}
	var handlerWithContext func(msg *D.Msg) (*D.Msg, error)
	if resolver.DefaultResolver != nil {
		dnsHandler := dns.NewHandler(resolver.DefaultResolver.(*dns.Resolver), resolver.DefaultHostMapper.(*dns.ResolverEnhancer))
		handlerWithContext = func(msg *D.Msg) (*D.Msg, error) {
			return dns.HandlerWithContext(dnsHandler, msg)
		}
	}

	handler := &ListenerHandler{sing.ListenerHandler{
		TcpIn: tcpIn,
		UdpIn: udpIn,
		Type:  C.TUN,
	}, dnsHijack, handlerWithContext}
	l := &Listener{
		closed:  false,
		options: options,
		handler: handler,
	}

	networkUpdateMonitor, err := tun.NewNetworkUpdateMonitor(handler)
	if err != nil {
		return nil, E.Cause(err, "create NetworkUpdateMonitor")
	}
	err = networkUpdateMonitor.Start()
	if err != nil {
		return nil, E.Cause(err, "start NetworkUpdateMonitor")
	}
	l.networkUpdateMonitor = networkUpdateMonitor

	defaultInterfaceMonitor, err := tun.NewDefaultInterfaceMonitor(networkUpdateMonitor, tun.DefaultInterfaceMonitorOptions{})
	if err != nil {
		_ = networkUpdateMonitor.Close()
		return nil, E.Cause(err, "create DefaultInterfaceMonitor")
	}
	defaultInterfaceMonitor.RegisterCallback(func(event int) error {
		generalInterface := dialer.GeneralInterface.Load()
		targetInterface := generalInterface
		autoDetectInterfaceName := defaultInterfaceMonitor.DefaultInterfaceName(netip.IPv4Unspecified())
		if autoDetectInterfaceName != "" && autoDetectInterfaceName != "<nil>" {
			targetInterface = autoDetectInterfaceName
		} else {
			log.Warnln("Auto detect interface name is empty.")
		}
		if dialer.DefaultInterface.Load() != targetInterface {
			log.Infoln("Use interface name: %s", targetInterface)

			dialer.DefaultInterface.Store(targetInterface)

			iface.FlushCache()
		}
		return nil
	})
	err = defaultInterfaceMonitor.Start()
	if err != nil {
		_ = networkUpdateMonitor.Close()
		return nil, E.Cause(err, "start DefaultInterfaceMonitor")
	}
	l.defaultInterfaceMonitor = defaultInterfaceMonitor

	tunOptions := tun.Options{
		Name:               tunName,
		MTU:                tunMTU,
		Inet4Address:       common.Map(options.Inet4Address, config.ListenPrefix.Build),
		Inet6Address:       common.Map(options.Inet6Address, config.ListenPrefix.Build),
		AutoRoute:          options.AutoRoute,
		StrictRoute:        options.StrictRoute,
		IncludeUID:         includeUID,
		ExcludeUID:         excludeUID,
		IncludeAndroidUser: options.IncludeAndroidUser,
		IncludePackage:     options.IncludePackage,
		ExcludePackage:     options.ExcludePackage,
		InterfaceMonitor:   defaultInterfaceMonitor,
		TableIndex:         2022,
	}

	//if C.IsAndroid {
	//	t.tunOptions.BuildAndroidRules(t.router.PackageManager(), t)
	//}
	tunIf, err := tun.Open(tunOptions)
	if err != nil {
		_ = networkUpdateMonitor.Close()
		_ = defaultInterfaceMonitor.Close()
		return nil, E.Cause(err, "configure tun interface")
	}
	l.tunIf = tunIf
	l.tunStack, err = tun.NewStack(options.Stack, tun.StackOptions{
		Context:                context.TODO(),
		Tun:                    tunIf,
		MTU:                    tunOptions.MTU,
		Name:                   tunOptions.Name,
		Inet4Address:           tunOptions.Inet4Address,
		Inet6Address:           tunOptions.Inet6Address,
		EndpointIndependentNat: options.EndpointIndependentNat,
		UDPTimeout:             udpTimeout,
		Handler:                handler,
		Logger:                 sing.Logger,
	})
	if err != nil {
		_ = networkUpdateMonitor.Close()
		_ = defaultInterfaceMonitor.Close()
		return nil, err
	}
	err = l.tunStack.Start()
	if err != nil {
		_ = networkUpdateMonitor.Close()
		_ = defaultInterfaceMonitor.Close()
		_ = tunIf.Close()
		return nil, err
	}
	sing.Logger.Info("started at ", tunOptions.Name)
	return l, nil
}

func uidToRange(uidList []uint32) []ranges.Range[uint32] {
	return common.Map(uidList, func(uid uint32) ranges.Range[uint32] {
		return ranges.NewSingle(uid)
	})
}

func parseRange(uidRanges []ranges.Range[uint32], rangeList []string) ([]ranges.Range[uint32], error) {
	for _, uidRange := range rangeList {
		if !strings.Contains(uidRange, ":") {
			return nil, E.New("missing ':' in range: ", uidRange)
		}
		subIndex := strings.Index(uidRange, ":")
		if subIndex == 0 {
			return nil, E.New("missing range start: ", uidRange)
		} else if subIndex == len(uidRange)-1 {
			return nil, E.New("missing range end: ", uidRange)
		}
		var start, end uint64
		var err error
		start, err = strconv.ParseUint(uidRange[:subIndex], 10, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range start")
		}
		end, err = strconv.ParseUint(uidRange[subIndex+1:], 10, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range end")
		}
		uidRanges = append(uidRanges, ranges.New(uint32(start), uint32(end)))
	}
	return uidRanges, nil
}

func (l *Listener) Close() {
	l.closed = true
	_ = common.Close(
		l.tunStack,
		l.tunIf,
		l.defaultInterfaceMonitor,
		l.networkUpdateMonitor,
	)
}

func (l *Listener) Config() config.Tun {
	return l.options
}
