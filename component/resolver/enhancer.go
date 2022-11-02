package resolver

import (
	"net/netip"
)

var DefaultHostMapper Enhancer

type Enhancer interface {
	FakeIPEnabled() bool
	MappingEnabled() bool
	IsFakeIP(netip.Addr) bool
	IsExistFakeIP(netip.Addr) bool
	FindHostByIP(netip.Addr) (string, bool)
}

func FakeIPEnabled() bool {
	if mapper := DefaultHostMapper; mapper != nil {
		return mapper.FakeIPEnabled()
	}

	return false
}

func MappingEnabled() bool {
	if mapper := DefaultHostMapper; mapper != nil {
		return mapper.MappingEnabled()
	}

	return false
}

func IsFakeIP(ip netip.Addr) bool {
	if mapper := DefaultHostMapper; mapper != nil {
		return mapper.IsFakeIP(ip)
	}

	return false
}

func IsExistFakeIP(ip netip.Addr) bool {
	if mapper := DefaultHostMapper; mapper != nil {
		return mapper.IsExistFakeIP(ip)
	}

	return false
}

func FindHostByIP(ip netip.Addr) (string, bool) {
	if mapper := DefaultHostMapper; mapper != nil {
		return mapper.FindHostByIP(ip)
	}

	return "", false
}
