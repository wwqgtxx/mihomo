package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/Dreamacro/clash/component/resolver"
)

var (
	dialMux                    sync.Mutex
	actualSingleDialContext    = singleDialContext
	actualDualStackDialContext = dualStackDialContext
	tcpConcurrent              = false
)

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
	cfg := &option{
		interfaceName: DefaultInterface.Load(),
		routingMark:   int(DefaultRoutingMark.Load()),
	}

	for _, o := range DefaultOptions {
		o(cfg)
	}

	for _, o := range options {
		o(cfg)
	}

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

func dialContext(ctx context.Context, network string, destination net.IP, port string, options []Option) (net.Conn, error) {
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

	var ip net.IP
	switch network {
	case "tcp4", "udp4":
		ip, err = resolver.ResolveIPv4WithResolver(host, resolver.DialerResolver)
	default:
		ip, err = resolver.ResolveIPv6WithResolver(host, resolver.DialerResolver)
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

		var ip net.IP
		if ipv6 {
			ip, result.error = resolver.ResolveIPv6WithResolver(host, resolver.DialerResolver)
		} else {
			ip, result.error = resolver.ResolveIPv4WithResolver(host, resolver.DialerResolver)
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

func concurrentDialContext(ctx context.Context, network string, destinations []net.IP, port string, options []Option) (net.Conn, error) {
	returned := make(chan struct{})
	defer close(returned)

	type dialResult struct {
		net.Conn
		error
		done bool
	}
	results := make(chan dialResult)

	startRacer := func(ctx context.Context, network string, destination net.IP, port string) {
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
	for i := 0; i < connCount; i++ {
		select {
		case res := <-results:
			if res.error == nil {
				return res.Conn, nil
			}
		case <-ctx.Done():
			break
		}
	}

	return nil, fmt.Errorf("all ips %v tcp shake hands failed", destinations)
}

func concurrentSingleDialContext(ctx context.Context, network, address string, options []Option) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	var ips []net.IP
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

		var ips []net.IP
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
