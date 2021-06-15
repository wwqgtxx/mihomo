package rules

import (
	"strconv"

	C "github.com/Dreamacro/clash/constant"
)

type Port struct {
	adapter  string
	port     string
	ruleType C.RuleType
}

func (p *Port) RuleType() C.RuleType {
	return p.ruleType
}

func (p *Port) Match(metadata *C.Metadata) bool {
	switch p.ruleType {
	case C.InPort:
		return metadata.InPort == p.port
	case C.SrcPort:
		return metadata.SrcPort == p.port
	}
	return metadata.DstPort == p.port
}

func (p *Port) Adapter() string {
	return p.adapter
}

func (p *Port) Payload() string {
	return p.port
}

func (p *Port) ShouldResolveIP() bool {
	return false
}

func NewPort(port string, adapter string, ruleType C.RuleType) (*Port, error) {
	_, err := strconv.Atoi(port)
	if err != nil {
		return nil, errPayload
	}
	return &Port{
		adapter:  adapter,
		port:     port,
		ruleType: ruleType,
	}, nil
}
