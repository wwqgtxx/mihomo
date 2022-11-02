package fakeip

import (
	"net/netip"

	"github.com/Dreamacro/clash/common/cache"
)

type memoryStore struct {
	cache *cache.LruCache
}

// GetByHost implements store.GetByHost
func (m *memoryStore) GetByHost(host string) (netip.Addr, bool) {
	if elm, exist := m.cache.Get(host); exist {
		ip := elm.(netip.Addr)

		// ensure ip --> host on head of linked list
		m.cache.Get(ipToUint(ip))
		return ip, true
	}

	return netip.Addr{}, false
}

// PutByHost implements store.PutByHost
func (m *memoryStore) PutByHost(host string, ip netip.Addr) {
	m.cache.Set(host, ip)
}

// GetByIP implements store.GetByIP
func (m *memoryStore) GetByIP(ip netip.Addr) (string, bool) {
	if elm, exist := m.cache.Get(ipToUint(ip)); exist {
		host := elm.(string)

		// ensure host --> ip on head of linked list
		m.cache.Get(host)
		return host, true
	}

	return "", false
}

// PutByIP implements store.PutByIP
func (m *memoryStore) PutByIP(ip netip.Addr, host string) {
	m.cache.Set(ipToUint(ip), host)
}

// DelByIP implements store.DelByIP
func (m *memoryStore) DelByIP(ip netip.Addr) {
	ipNum := ipToUint(ip)
	if elm, exist := m.cache.Get(ipNum); exist {
		m.cache.Delete(elm.(string))
	}
	m.cache.Delete(ipNum)
}

// Exist implements store.Exist
func (m *memoryStore) Exist(ip netip.Addr) bool {
	return m.cache.Exist(ipToUint(ip))
}

// CloneTo implements store.CloneTo
// only for memoryStore to memoryStore
func (m *memoryStore) CloneTo(store store) {
	if ms, ok := store.(*memoryStore); ok {
		m.cache.CloneTo(ms.cache)
	}
}
