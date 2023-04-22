//go:build !linux

package ipset

import (
	"net/netip"
)

// Always return false in non-linux
func Test(setName string, ip netip.Addr) (bool, error) {
	return false, nil
}

// Always pass in non-linux
func Verify(setName string) error {
	return nil
}
