package dns

import (
	"net/netip"
	"strings"

	"github.com/metacubex/mihomo/component/mmdb"
	"github.com/metacubex/mihomo/component/trie"
)

type fallbackIPFilter interface {
	Match(netip.Addr) bool
}

type geoipFilter struct {
	code string
}

func (gf *geoipFilter) Match(ip netip.Addr) bool {
	record, _ := mmdb.Instance().Country(ip.AsSlice())
	return !strings.EqualFold(record.Country.IsoCode, gf.code) && !ip.IsPrivate()
}

type ipnetFilter struct {
	ipnet netip.Prefix
}

func (inf *ipnetFilter) Match(ip netip.Addr) bool {
	return inf.ipnet.Contains(ip)
}

type fallbackDomainFilter interface {
	Match(domain string) bool
}

type domainFilter struct {
	tree *trie.DomainSet
}

func NewDomainFilter(domains []string) *domainFilter {
	tree := trie.New[struct{}]()
	for _, domain := range domains {
		tree.Insert(domain, struct{}{})
	}
	df := domainFilter{tree: tree.NewDomainSet()}
	return &df
}

func (df *domainFilter) Match(domain string) bool {
	return df.tree.Has(domain)
}
