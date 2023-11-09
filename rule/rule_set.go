package rules

import (
	C "github.com/metacubex/mihomo/constant"
)

type RuleSet struct {
	ruleProviderName string
	adapter          string
}

func (r *RuleSet) RuleType() C.RuleType {
	return C.RuleSet
}

func (r *RuleSet) Match(metadata *C.Metadata) (bool, string) {
	// parse in rule.go
	return false, ""
}

func (r *RuleSet) Adapter() string {
	return r.adapter
}

func (r *RuleSet) Payload() string {
	return r.ruleProviderName
}

func (r *RuleSet) ShouldResolveIP() bool {
	return false
}

func (r *RuleSet) ShouldFindProcess() bool {
	return false
}

func NewRuleSet(name string, adapter string) *RuleSet {
	return &RuleSet{
		ruleProviderName: name,
		adapter:          adapter,
	}
}
