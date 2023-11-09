package dns

import (
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/provider"
)

type dnsPolicy interface {
	Match(domain string) []dnsClient
}

type domainTriePolicy struct {
	*trie.DomainTrie[[]dnsClient]
}

func (p domainTriePolicy) Match(domain string) []dnsClient {
	record := p.DomainTrie.Search(domain)
	if record != nil {
		return record.Data()
	}
	return nil
}

type domainSetPolicy struct {
	domainSetProvider provider.RuleProvider
	dnsClients        []dnsClient
}

func (p domainSetPolicy) Match(domain string) []dnsClient {
	metadata := &C.Metadata{Host: domain}
	for _, rule := range p.domainSetProvider.Rules() {
		if ok, _ := rule.Match(metadata); ok {
			return p.dnsClients
		}
	}
	return nil
}
