package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"

	"github.com/Dreamacro/clash/component/resolver"
)

var (
	dialMux                    sync.Mutex
	actualSingleDialContext    = singleDialContext
	actualDualStackDialContext = dualStackDialContext
	tcpConcurrent              = false
)

func ParseNetwork(network string, addr netip.Addr) string {
	if runtime.GOOS == "windows" { // fix bindIfaceToListenConfig() in windows force bind to an ipv4 address
		if !strings.HasSuffix(network, "4") &&
			!strings.HasSuffix(network, "6") &&
			addr.Unmap().Is6() {
			network += "6"
		}
	}
	return network
}

func DialContext(ctx context.Context, network, address string, options ...Option) (net.Conn, error) {
	switch network {
	case "tcp4", "tcp6", "udp4", "udp6":
		return actualSingleDialContext(ctx, network, address, options)
	case "tcp", "udp":
		return actualDualStackDialContext(ctx, network, address, options)
	default:
		return nil, errors.New("network invalid")
	}
}

func ListenPacket(ctx context.Context, network, address string, options ...Option) (net.PacketConn, error) {
	cfg := applyOptions(options...)

	lc := &net.ListenConfig{}
	if cfg.interfaceName != "" {
		addr, err := bindIfaceToListenConfig(cfg.interfaceName, lc, network, address)
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

func SetDial(concurrent bool) {
	dialMux.Lock()
	tcpConcurrent = concurrent
	if concurrent {
		actualSingleDialContext = concurrentSingleDialContext
		actualDualStackDialContext = concurrentDualStackDialContext
	} else {
		actualSingleDialContext = singleDialContext
		actualDualStackDialContext = dualStackDialContext
	}

	dialMux.Unlock()
}

func GetDial() bool {
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

func dialContext(ctx context.Context, network string, destination netip.Addr, port string, options []Option) (net.Conn, error) {
	opt := applyOptions(options...)

	dialer := &net.Dialer{}
	if opt.interfaceName != "" {
		if err := bindIfaceToDialer(opt.interfaceName, dialer, network, destination); err != nil {
			return nil, err
		}
	}
	if opt.routingMark != 0 {
		bindMarkToDialer(opt.routingMark, dialer, network, destination)
	}

	return dialer.DialContext(ctx, network, net.JoinHostPort(destination.String(), port))
}

func singleDialContext(ctx context.Context, network, address string, options []Option) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	var ip netip.Addr
	switch network {
	case "tcp4", "udp4":
		ip, err = resolver.ResolveIPv4WithResolver(ctx, host, resolver.DialerResolver)
	default:
		ip, err = resolver.ResolveIPv6WithResolver(ctx, host, resolver.DialerResolver)
	}
	if err != nil {
		return nil, err
	}

	return dialContext(ctx, network, ip, port, options)
}

func dualStackDialContext(ctx context.Context, network, address string, options []Option) (net.Conn, error) {
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
			ip, result.error = resolver.ResolveIPv6WithResolver(ctx, host, resolver.DialerResolver)
		} else {
			ip, result.error = resolver.ResolveIPv4WithResolver(ctx, host, resolver.DialerResolver)
		}
		if result.error != nil {
			return
		}
		result.resolved = true

		result.Conn, result.error = dialContext(ctx, network, ip, port, options)
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

func concurrentDialContext(ctx context.Context, network string, destinations []netip.Addr, port string, options []Option) (net.Conn, error) {
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
		result.Conn, result.error = dialContext(ctx, network, destination, port, options)
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

func concurrentSingleDialContext(ctx context.Context, network, address string, options []Option) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	var ips []netip.Addr
	switch network {
	case "tcp4", "udp4":
		ips, err = resolver.LookupIPv4WithResolver(ctx, host, resolver.DialerResolver)
	default:
		ips, err = resolver.LookupIPv6WithResolver(ctx, host, resolver.DialerResolver)
	}
	if err != nil {
		return nil, err
	}

	return concurrentDialContext(ctx, network, ips, port, options)
}

func concurrentDualStackDialContext(ctx context.Context, network, address string, options []Option) (net.Conn, error) {
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
			ips, result.error = resolver.LookupIPv6WithResolver(ctx, host, resolver.DialerResolver)
		} else {
			ips, result.error = resolver.LookupIPv4WithResolver(ctx, host, resolver.DialerResolver)
		}
		if result.error != nil {
			return
		}
		result.resolved = true

		result.Conn, result.error = concurrentDialContext(ctx, network, ips, port, options)
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
	opt option
}

func (d Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return DialContext(ctx, network, address, WithOption(d.opt))
}

func (d Dialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	return ListenPacket(ctx, ParseNetwork(network, rAddrPort.Addr()), address, WithOption(d.opt))
}

func NewDialer(options ...Option) Dialer {
	opt := applyOptions(options...)
	return Dialer{opt: *opt}
}
