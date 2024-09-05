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
	tunnel     provider.Tunnel
	name       string
	dnsClients []dnsClient
}

func (p domainSetPolicy) Match(domain string) []dnsClient {
	if ruleProvider, ok := p.tunnel.RuleProviders()[p.name]; ok {
		metadata := &C.Metadata{Host: domain}
		if ok := ruleProvider.Match(metadata); ok {
			return p.dnsClients
		}
	}
	return nil
}
