package rules

import (
	"github.com/Dreamacro/clash/component/trie"
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

type DomainTrie struct {
	domain  string
	adapter string
	dt      *trie.DomainTrie
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

func NewDomainTrie(domain string, adapter string) (*DomainTrie, error) {
	domain = strings.ToLower(domain)
	dt := trie.New()
	err := dt.Insert(domain, "")
	return &DomainTrie{
		domain:  domain,
		adapter: adapter,
		dt:      dt,
	}, err
}
