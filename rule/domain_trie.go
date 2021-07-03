package rules

import (
	"strings"

	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"
)

type DomainTrie struct {
	domain  string
	adapter string
	dt      *trie.DomainTrie
	insertN int
}

func (d *DomainTrie) RuleType() C.RuleType {
	return C.DomainTrie
}

func (d *DomainTrie) Match(metadata *C.Metadata) bool {
	if metadata.AddrType != C.AtypDomainName {
		return false
	}
	return d.dt.Search(metadata.Host) != nil
}

func (d *DomainTrie) Adapter() string {
	return d.adapter
}

func (d *DomainTrie) Payload() string {
	return d.domain
}

func (d *DomainTrie) ShouldResolveIP() bool {
	return false
}

func (d *DomainTrie) Insert(domain string) error {
	domain = strings.ToLower(domain)
	err := d.dt.Insert(domain, "")
	if err != nil {
		return err
	}
	d.insertN++
	return nil
}

func newEmptyDomainTrie() *DomainTrie {
	dt := trie.New()
	return &DomainTrie{
		dt:      dt,
		insertN: 0,
	}
}

func NewDomainTrie(domain string, adapter string) (*DomainTrie, error) {
	dt := newEmptyDomainTrie()
	dt.adapter = adapter
	err := dt.Insert(domain)
	return dt, err
}
