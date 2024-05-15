package rules

import (
	C "github.com/metacubex/mihomo/constant"

	"github.com/dlclark/regexp2"
)

type DomainRegex struct {
	regex   *regexp2.Regexp
	adapter string
}

func (dr *DomainRegex) RuleType() C.RuleType {
	return C.DomainRegex
}

func (dr *DomainRegex) Match(metadata *C.Metadata) (bool, string) {
	domain := metadata.RuleHost()
	match, _ := dr.regex.MatchString(domain)
	return match, dr.adapter
}

func (dr *DomainRegex) Adapter() string {
	return dr.adapter
}

func (dr *DomainRegex) Payload() string {
	return dr.regex.String()
}

func (dr *DomainRegex) ShouldResolveIP() bool {
	return false
}

func (dr *DomainRegex) ShouldFindProcess() bool {
	return false
}

func NewDomainRegex(regex string, adapter string) (*DomainRegex, error) {
	r, err := regexp2.Compile(regex, regexp2.IgnoreCase)
	if err != nil {
		return nil, err
	}
	return &DomainRegex{
		regex:   r,
		adapter: adapter,
	}, nil
}

//var _ C.Rule = (*DomainRegex)(nil)
