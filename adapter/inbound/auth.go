package inbound

import (
	"net"
	"net/netip"
)

var skipAuthPrefixes []netip.Prefix

func SetSkipAuthPrefixes(prefixes []netip.Prefix) {
	skipAuthPrefixes = prefixes
}

func SkipAuthPrefixes() []netip.Prefix {
	return skipAuthPrefixes
}

func SkipAuthRemoteAddr(addr net.Addr) bool {
	if addr, _, err := parseAddr(addr); err == nil {
		for _, prefix := range skipAuthPrefixes {
			if prefix.Contains(addr) {
				return true
			}
		}
	}
	return false
}
