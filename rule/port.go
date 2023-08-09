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
	portL    uint16
	portR    uint16
}

func (p *Port) RuleType() C.RuleType {
	return p.ruleType
}

func (p *Port) Match(metadata *C.Metadata) (bool, string) {
	targetPort := metadata.DstPort
	switch p.ruleType {
	case C.InPort:
		targetPort = metadata.InPort
	case C.SrcPort:
		targetPort = metadata.SrcPort
	}
	port := targetPort
	return port >= p.portL && port <= p.portR, p.adapter
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

func (p *Port) ShouldFindProcess() bool {
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
	var uint64Port uint64
	switch len(portS) {
	case 1:
		uint64Port, err = strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, err
		}
		p.portL = uint16(uint64Port)
		p.portR = p.portL
	case 2:
		uint64Port, err = strconv.ParseUint(portS[0], 10, 16)
		if err != nil {
			return nil, err
		}
		p.portL = uint16(uint64Port)
		uint64Port, err = strconv.ParseUint(portS[1], 10, 16)
		if err != nil {
			return nil, err
		}
		p.portR = uint16(uint64Port)
	default:
		return nil, errPayload
	}
	return p, nil
}
