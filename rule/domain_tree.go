package rules

import (
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
)

type DomainTree struct {
	Domain    // for C.Rule interface
	dt        *trie.DomainTrie[struct{}]
	ds        *trie.DomainSet
	ruleCount int
}

func (d *DomainTree) RuleCount() int {
	return d.ruleCount
}

func (d *DomainTree) RuleType() C.RuleType {
	return C.DomainTree
}

func (d *DomainTree) Match(metadata *C.Metadata) (bool, string) {
	return d.ds.Has(metadata.RuleHost()), d.adapter
}

func (d *DomainTree) Insert(domain string) error {
	err := d.dt.Insert(domain, struct{}{})
	if err != nil {
		return err
	}
	d.ruleCount++
	return nil
}

func (d *DomainTree) FinishInsert() {
	d.ds = d.dt.NewDomainSet()
	d.dt = nil
}

func NewDomainTree() *DomainTree {
	return &DomainTree{
		Domain:    Domain{},
		dt:        trie.New[struct{}](),
		ds:        nil,
		ruleCount: 0,
	}
}
