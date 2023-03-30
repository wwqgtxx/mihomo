package rules

import (
	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/socks5"
)

type DomainTree struct {
	Domain    // for C.Rule interface
	dt        *trie.DomainSet
	ruleCount int
}

func (d *DomainTree) RuleCount() int {
	return d.ruleCount
}

func (d *DomainTree) RuleType() C.RuleType {
	return C.DomainTree
}

func (d *DomainTree) Match(metadata *C.Metadata) (bool, string) {
	if metadata.AddrType() != socks5.AtypDomainName {
		return false, ""
	}
	return d.dt.Has(metadata.Host), d.adapter
}

func NewDomainTree(domains []string) (*DomainTree, error) {
	dt := trie.NewDomainSet(domains)
	return &DomainTree{
		Domain:    Domain{},
		dt:        dt,
		ruleCount: len(domains),
	}, nil
}
