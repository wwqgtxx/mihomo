package resolver

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/Dreamacro/clash/component/trie"
)

var (
	// DefaultResolver aim to resolve ip
	DefaultResolver Resolver

	// DialerResolver resolve ip only for outbound Dialer
	DialerResolver Resolver

	// DisableIPv6 means don't resolve ipv6 host
	// default value is true
	DisableIPv6 = true

	// DefaultHosts aim to resolve hosts
	DefaultHosts = trie.New()

	// DefaultDNSTimeout defined the default dns request timeout
	DefaultDNSTimeout = time.Second * 5
)

var (
	ErrIPNotFound   = errors.New("couldn't find ip")
	ErrIPVersion    = errors.New("ip version error")
	ErrIPv6Disabled = errors.New("ipv6 disabled")
)

type Resolver interface {
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
	LookupIPv4(ctx context.Context, host string) ([]net.IP, error)
	LookupIPv6(ctx context.Context, host string) ([]net.IP, error)
	ResolveIP(host string) (ip net.IP, err error)
	ResolveIPv4(host string) (ip net.IP, err error)
	ResolveIPv6(host string) (ip net.IP, err error)
}

// LookupIPv4WithResolver same as LookupIPv4, but with a resolver
func LookupIPv4WithResolver(ctx context.Context, host string, r Resolver) ([]net.IP, error) {
	if node := DefaultHosts.Search(host); node != nil {
		if ip := node.Data.(net.IP).To4(); ip != nil {
			return []net.IP{ip}, nil
		}
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if !strings.Contains(host, ":") {
			return []net.IP{ip}, nil
		}
		return nil, ErrIPVersion
	}

	if r != nil {
		return r.LookupIPv4(ctx, host)
	}

	if DefaultResolver != nil {
		return DefaultResolver.LookupIPv4(ctx, host)
	}

	ctx, cancel := context.WithTimeout(context.Background(), DefaultDNSTimeout)
	defer cancel()
	ipAddrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	} else if len(ipAddrs) == 0 {
		return nil, ErrIPNotFound
	}

	return ipAddrs, nil
}

// LookupIPv4 with a host, return ipv4 list
func LookupIPv4(ctx context.Context, host string) ([]net.IP, error) {
	return LookupIPv4WithResolver(ctx, host, nil)
}

// ResolveIPv4WithResolver same as ResolveIPv4, but with a resolver
func ResolveIPv4WithResolver(host string, r Resolver) (net.IP, error) {
	ips, err := LookupIPv4WithResolver(context.Background(), host, r)
	if err != nil {
		return nil, err
	} else if len(ips) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}
	return ips[rand.Intn(len(ips))], nil
}

// ResolveIPv4 with a host, return ipv4
func ResolveIPv4(host string) (net.IP, error) {
	return ResolveIPv4WithResolver(host, DefaultResolver)
}

// LookupIPv6WithResolver same as LookupIPv6, but with a resolver
func LookupIPv6WithResolver(ctx context.Context, host string, r Resolver) ([]net.IP, error) {
	if DisableIPv6 {
		return nil, ErrIPv6Disabled
	}

	if node := DefaultHosts.Search(host); node != nil {
		if ip := node.Data.(net.IP).To16(); ip != nil {
			return []net.IP{ip}, nil
		}
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if strings.Contains(host, ":") {
			return []net.IP{ip}, nil
		}
		return nil, ErrIPVersion
	}

	if r != nil {
		return r.LookupIPv6(ctx, host)
	}
	if DefaultResolver != nil {
		return DefaultResolver.LookupIPv6(ctx, host)
	}

	ctx, cancel := context.WithTimeout(context.Background(), DefaultDNSTimeout)
	defer cancel()
	ipAddrs, err := net.DefaultResolver.LookupIP(ctx, "ip6", host)
	if err != nil {
		return nil, err
	} else if len(ipAddrs) == 0 {
		return nil, ErrIPNotFound
	}

	return ipAddrs, nil
}

// LookupIPv6 with a host, return ipv6 list
func LookupIPv6(ctx context.Context, host string) ([]net.IP, error) {
	return LookupIPv6WithResolver(ctx, host, DefaultResolver)
}

// ResolveIPv6WithResolver same as ResolveIPv6, but with a resolver
func ResolveIPv6WithResolver(host string, r Resolver) (net.IP, error) {
	ips, err := LookupIPv6WithResolver(context.Background(), host, r)
	if err != nil {
		return nil, err
	} else if len(ips) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}
	return ips[rand.Intn(len(ips))], nil
}

func ResolveIPv6(host string) (net.IP, error) {
	return ResolveIPv6WithResolver(host, DefaultResolver)
}

// LookupIPWithResolver same as LookupIP, but with a resolver
func LookupIPWithResolver(ctx context.Context, host string, r Resolver) ([]net.IP, error) {
	if node := DefaultHosts.Search(host); node != nil {
		return []net.IP{node.Data.(net.IP)}, nil
	}

	if r != nil {
		if DisableIPv6 {
			return r.LookupIPv4(ctx, host)
		}
		return r.LookupIP(ctx, host)
	} else if DisableIPv6 {
		return LookupIPv4(ctx, host)
	}

	ip := net.ParseIP(host)
	if ip != nil {
		return []net.IP{ip}, nil
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	} else if len(ips) == 0 {
		return nil, ErrIPNotFound
	}

	return ips, nil
}

// LookupIP with a host, return ip
func LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	return LookupIPWithResolver(ctx, host, DefaultResolver)
}

// ResolveIPWithResolver same as ResolveIP, but with a resolver
func ResolveIPWithResolver(host string, r Resolver) (net.IP, error) {
	ips, err := LookupIPWithResolver(context.Background(), host, r)
	if err != nil {
		return nil, err
	} else if len(ips) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrIPNotFound, host)
	}
	return ips[rand.Intn(len(ips))], nil
}

// ResolveIP with a host, return ip
func ResolveIP(host string) (net.IP, error) {
	return ResolveIPWithResolver(host, DefaultResolver)
}
