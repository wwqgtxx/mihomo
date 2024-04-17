package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
)

const (
	DefaultTCPTimeout = 5 * time.Second
	DefaultUDPTimeout = DefaultTCPTimeout
)

var (
	dialMux                    sync.Mutex
	actualSingleDialContext    = singleDialContext
	actualDualStackDialContext = dualStackDialContext
	tcpConcurrent              = false
)

func DialContext(ctx context.Context, network, address string, options ...Option) (net.Conn, error) {
	opt := applyOptions(options...)

	switch network {
	case "tcp4", "tcp6", "udp4", "udp6":
		return actualSingleDialContext(ctx, network, address, opt)
	case "tcp", "udp":
		return actualDualStackDialContext(ctx, network, address, opt)
	default:
		return nil, errors.New("network invalid")
	}
}

func ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort, options ...Option) (net.PacketConn, error) {
	cfg := applyOptions(options...)

	lc := &net.ListenConfig{}
	if cfg.interfaceName != "" {
		bind := bindIfaceToListenConfig
		if cfg.fallbackBind {
			bind = fallbackBindIfaceToListenConfig
		}
		addr, err := bind(cfg.interfaceName, lc, network, address, rAddrPort)
		if err != nil {
			return nil, err
		}
		address = addr
	}
	if cfg.addrReuse {
		addrReuseToListenConfig(lc)
	}
	if cfg.routingMark != 0 {
		bindMarkToListenConfig(cfg.routingMark, lc, network, address)
	}

	return lc.ListenPacket(ctx, network, address)
}

func SetTcpConcurrent(concurrent bool) {
	dialMux.Lock()
	defer dialMux.Unlock()
	tcpConcurrent = concurrent
	if concurrent {
		actualSingleDialContext = concurrentSingleDialContext
		actualDualStackDialContext = concurrentDualStackDialContext
	} else {
		actualSingleDialContext = singleDialContext
		actualDualStackDialContext = dualStackDialContext
	}
}

func GetTcpConcurrent() bool {
	dialMux.Lock()
	defer dialMux.Unlock()
	return tcpConcurrent
}

func applyOptions(options ...Option) *option {
	opt := &option{
		interfaceName: DefaultInterface.Load(),
		routingMark:   int(DefaultRoutingMark.Load()),
	}

	for _, o := range DefaultOptions {
		o(opt)
	}

	for _, o := range options {
		o(opt)
	}

	return opt
}

func dialContext(ctx context.Context, network string, destination netip.Addr, port string, opt *option) (net.Conn, error) {
	address := net.JoinHostPort(destination.String(), port)

	netDialer := opt.netDialer
	switch netDialer.(type) {
	case nil:
		netDialer = &net.Dialer{}
	case *net.Dialer:
		_netDialer := *netDialer.(*net.Dialer)
		netDialer = &_netDialer // make a copy
	default:
		return netDialer.DialContext(ctx, network, address)
	}

	dialer := netDialer.(*net.Dialer)
	if opt.interfaceName != "" {
		bind := bindIfaceToDialer
		if opt.fallbackBind {
			bind = fallbackBindIfaceToDialer
		}
		if err := bind(opt.interfaceName, dialer, network, destination); err != nil {
			return nil, err
		}
	}
	if opt.routingMark != 0 {
		bindMarkToDialer(opt.routingMark, dialer, network, destination)
	}
	if opt.mpTcp {
		setMultiPathTCP(dialer)
	}
	if opt.tfo {
		return dialTFO(ctx, *dialer, network, address)
	}
	return dialer.DialContext(ctx, network, address)
}

func singleDialContext(ctx context.Context, network, address string, opt *option) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	var ip netip.Addr
	switch network {
	case "tcp4", "udp4":
		if opt.resolver == nil {
			ip, err = resolver.ResolveIPv4WithResolver(ctx, host, resolver.DialerResolver)
		} else {
			ip, err = resolver.ResolveIPv4WithResolver(ctx, host, opt.resolver)
		}
	default:
		if opt.resolver == nil {
			ip, err = resolver.ResolveIPv6WithResolver(ctx, host, resolver.DialerResolver)
		} else {
			ip, err = resolver.ResolveIPv6WithResolver(ctx, host, opt.resolver)
		}
	}
	if err != nil {
		return nil, err
	}

	return dialContext(ctx, network, ip, port, opt)
}

func dualStackDialContext(ctx context.Context, network, address string, opt *option) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	returned := make(chan struct{})
	defer close(returned)

	type dialResult struct {
		net.Conn
		error
		resolved bool
		ipv6     bool
		done     bool
	}
	results := make(chan dialResult)
	var primary, fallback dialResult

	startRacer := func(ctx context.Context, network, host string, ipv6 bool) {
		result := dialResult{ipv6: ipv6, done: true}
		defer func() {
			select {
			case results <- result:
			case <-returned:
				if result.Conn != nil {
					_ = result.Conn.Close()
				}
			}
		}()

		var ip netip.Addr
		if ipv6 {
			if opt.resolver == nil {
				ip, result.error = resolver.ResolveIPv6WithResolver(ctx, host, resolver.DialerResolver)
			} else {
				ip, result.error = resolver.ResolveIPv6WithResolver(ctx, host, opt.resolver)
			}
		} else {
			if opt.resolver == nil {
				ip, result.error = resolver.ResolveIPv4WithResolver(ctx, host, resolver.DialerResolver)
			} else {
				ip, result.error = resolver.ResolveIPv4WithResolver(ctx, host, opt.resolver)
			}
		}
		if result.error != nil {
			return
		}
		result.resolved = true

		result.Conn, result.error = dialContext(ctx, network, ip, port, opt)
	}

	go startRacer(ctx, network+"4", host, false)
	go startRacer(ctx, network+"6", host, true)

	for res := range results {
		if res.error == nil {
			return res.Conn, nil
		}

		if !res.ipv6 {
			primary = res
		} else {
			fallback = res
		}

		if primary.done && fallback.done {
			if primary.resolved {
				return nil, primary.error
			} else if fallback.resolved {
				return nil, fallback.error
			} else {
				return nil, primary.error
			}
		}
	}

	return nil, errors.New("never touched")
}

func concurrentDialContext(ctx context.Context, network string, destinations []netip.Addr, port string, opt *option) (net.Conn, error) {
	returned := make(chan struct{})
	defer close(returned)

	type dialResult struct {
		net.Conn
		error
		done bool
	}
	results := make(chan dialResult)

	startRacer := func(ctx context.Context, network string, destination netip.Addr, port string) {
		result := dialResult{done: true}
		defer func() {
			select {
			case results <- result:
			case <-returned:
				if result.Conn != nil {
					_ = result.Conn.Close()
				}
			}
		}()
		result.Conn, result.error = dialContext(ctx, network, destination, port, opt)
	}

	for _, destination := range destinations {
		go startRacer(ctx, network, destination, port)
	}

	connCount := len(destinations)
	var firstErr error
	for i := 0; i < connCount; i++ {
		select {
		case res := <-results:
			if res.error == nil {
				return res.Conn, nil
			} else if firstErr == nil {
				firstErr = res.error
			}
		case <-ctx.Done():
			if firstErr == nil {
				firstErr = ctx.Err()
			}
			break
		}
	}

	return nil, fmt.Errorf("all ips %v tcp shake hands failed, the first error is: %w", destinations, firstErr)
}

func concurrentSingleDialContext(ctx context.Context, network, address string, opt *option) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	var ips []netip.Addr
	switch network {
	case "tcp4", "udp4":
		if opt.resolver == nil {
			ips, err = resolver.LookupIPv4WithResolver(ctx, host, resolver.DialerResolver)
		} else {
			ips, err = resolver.LookupIPv4WithResolver(ctx, host, opt.resolver)
		}
	default:
		if opt.resolver == nil {
			ips, err = resolver.LookupIPv6WithResolver(ctx, host, resolver.DialerResolver)
		} else {
			ips, err = resolver.LookupIPv6WithResolver(ctx, host, opt.resolver)
		}
	}
	if err != nil {
		return nil, err
	}

	return concurrentDialContext(ctx, network, ips, port, opt)
}

func concurrentDualStackDialContext(ctx context.Context, network, address string, opt *option) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	returned := make(chan struct{})
	defer close(returned)

	type dialResult struct {
		net.Conn
		error
		resolved bool
		ipv6     bool
		done     bool
	}
	results := make(chan dialResult)
	var primary, fallback dialResult

	startRacer := func(ctx context.Context, network, host string, ipv6 bool) {
		result := dialResult{ipv6: ipv6, done: true}
		defer func() {
			select {
			case results <- result:
			case <-returned:
				if result.Conn != nil {
					_ = result.Conn.Close()
				}
			}
		}()

		var ips []netip.Addr
		if ipv6 {
			if opt.resolver == nil {
				ips, result.error = resolver.LookupIPv6WithResolver(ctx, host, resolver.DialerResolver)
			} else {
				ips, result.error = resolver.LookupIPv6WithResolver(ctx, host, opt.resolver)
			}
		} else {
			if opt.resolver == nil {
				ips, result.error = resolver.LookupIPv4WithResolver(ctx, host, resolver.DialerResolver)
			} else {
				ips, result.error = resolver.LookupIPv4WithResolver(ctx, host, opt.resolver)
			}
		}
		if result.error != nil {
			return
		}
		result.resolved = true

		result.Conn, result.error = concurrentDialContext(ctx, network, ips, port, opt)
	}

	go startRacer(ctx, network+"4", host, false)
	go startRacer(ctx, network+"6", host, true)

	for res := range results {
		if res.error == nil {
			return res.Conn, nil
		}

		if !res.ipv6 {
			primary = res
		} else {
			fallback = res
		}

		if primary.done && fallback.done {
			if primary.resolved {
				return nil, primary.error
			} else if fallback.resolved {
				return nil, fallback.error
			} else {
				return nil, primary.error
			}
		}
	}

	return nil, errors.New("never touched")
}

type Dialer struct {
	Opt option
}

func (d Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return DialContext(ctx, network, address, WithOption(d.Opt))
}

func (d Dialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	opt := WithOption(d.Opt)
	if rAddrPort.Addr().Unmap().IsLoopback() {
		// avoid "The requested address is not valid in its context."
		opt = WithInterface("")
	}
	return ListenPacket(ctx, ParseNetwork(network, rAddrPort.Addr()), address, rAddrPort, opt)
}

func NewDialer(options ...Option) Dialer {
	opt := applyOptions(options...)
	return Dialer{Opt: *opt}
}
