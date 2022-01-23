package rules

import (
	"strconv"
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

type Port struct {
	adapter  string
	port     string
	ruleType C.RuleType
	portL    int
	portR    int
}

func (p *Port) RuleType() C.RuleType {
	return p.ruleType
}

func (p *Port) Match(metadata *C.Metadata) bool {
	targetPort := metadata.DstPort
	switch p.ruleType {
	case C.InPort:
		targetPort = metadata.InPort
	case C.SrcPort:
		targetPort = metadata.SrcPort
	}
	port, err := strconv.Atoi(targetPort)
	if err != nil {
		return false
	}
	return port >= p.portL && port <= p.portR
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
	p := &Port{
		adapter:  adapter,
		port:     port,
		ruleType: ruleType,
	}
	var err error
	portS := strings.Split(port, "-")
	switch len(portS) {
	case 1:
		p.portL, err = strconv.Atoi(port)
		if err != nil {
			return nil, err
		}
		p.portR = p.portL
	case 2:
		p.portL, err = strconv.Atoi(portS[0])
		if err != nil {
			return nil, err
		}
		p.portR, err = strconv.Atoi(portS[1])
		if err != nil {
			return nil, err
		}
	default:
		return nil, errPayload
	}
	return p, nil
}
