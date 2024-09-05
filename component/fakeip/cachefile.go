package fakeip

import (
	"net/netip"

	"github.com/metacubex/mihomo/component/profile/cachefile"
)

type cachefileStore struct {
	cache *cachefile.CacheFile
}

// GetByHost implements store.GetByHost
func (c *cachefileStore) GetByHost(host string) (netip.Addr, bool) {
	elm := c.cache.GetFakeip([]byte(host))
	ip := netip.Addr{}
	if elm == nil {
		return ip, false
	}
	_ = (&ip).UnmarshalBinary(elm)
	return ip, true
}

// PutByHost implements store.PutByHost
func (c *cachefileStore) PutByHost(host string, ip netip.Addr) {
	b, _ := ip.MarshalBinary()
	_ = c.cache.PutFakeip([]byte(host), b)
}

// GetByIP implements store.GetByIP
func (c *cachefileStore) GetByIP(ip netip.Addr) (string, bool) {
	b, _ := ip.MarshalBinary()
	elm := c.cache.GetFakeip(b)
	if elm == nil {
		return "", false
	}
	return string(elm), true
}

// PutByIP implements store.PutByIP
func (c *cachefileStore) PutByIP(ip netip.Addr, host string) {
	b, _ := ip.MarshalBinary()
	_ = c.cache.PutFakeip(b, []byte(host))
}

// DelByIP implements store.DelByIP
func (c *cachefileStore) DelByIP(ip netip.Addr) {
	b, _ := ip.MarshalBinary()
	_ = c.cache.DelFakeipPair(b, c.cache.GetFakeip(b))
}

// Exist implements store.Exist
func (c *cachefileStore) Exist(ip netip.Addr) bool {
	_, exist := c.GetByIP(ip)
	return exist
}

// CloneTo implements store.CloneTo
// already persistence
func (c *cachefileStore) CloneTo(store store) {}

// FlushFakeIP implements store.FlushFakeIP
func (c *cachefileStore) FlushFakeIP() error {
	return c.cache.FlushFakeIP()
}
