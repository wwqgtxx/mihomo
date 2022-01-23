package rules

import (
	"fmt"
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

func trimArr(arr []string) (r []string) {
	for _, e := range arr {
		r = append(r, strings.Trim(e, " "))
	}
	return
}

func ParseRule(tp, payload, target string, params []string) (C.Rule, error) {
	var (
		parseErr error
		parsed   C.Rule
	)

	switch tp {
	case "DOMAIN":
		parsed = NewDomain(payload, target)
	case "DOMAIN-SUFFIX":
		parsed = NewDomainSuffix(payload, target)
	case "DOMAIN-KEYWORD":
		parsed = NewDomainKeyword(payload, target)
	case "GEOIP":
		noResolve := HasNoResolve(params)
		parsed = NewGEOIP(payload, target, noResolve)
	case "IP-CIDR", "IP-CIDR6":
		noResolve := HasNoResolve(params)
		parsed, parseErr = NewIPCIDR(payload, target, WithIPCIDRNoResolve(noResolve))
	case "SRC-IP-CIDR":
		parsed, parseErr = NewIPCIDR(payload, target, WithIPCIDRSourceIP(true), WithIPCIDRNoResolve(true))
	case "SRC-PORT":
		parsed, parseErr = NewPort(payload, target, C.SrcPort)
	case "DST-PORT":
		parsed, parseErr = NewPort(payload, target, C.DstPort)
	case "IN-PORT":
		parsed, parseErr = NewPort(payload, target, C.InPort)
	case "PROCESS-NAME":
		parsed, parseErr = NewProcess(payload, target)
	case "NETWORK":
		parsed, parseErr = NewNetwork(payload, target)
	case "TYPE":
		parsed, parseErr = NewType(payload, target)
	case "MATCH":
		parsed = NewMatch(target)
	case "RULE-SET":
		if target == "" { // don't allow use RULE-SET in a Rule Providers' classical config file
			parseErr = fmt.Errorf("unsupported rule type %s", tp)
			break
		}
		parsed = NewRuleSet(payload, target)
	case "NOT":
		parsed, parseErr = NewNOT(payload, target)
	case "AND":
		parsed, parseErr = NewAND(payload, target)
	case "OR":
		parsed, parseErr = NewOR(payload, target)
	default:
		parseErr = fmt.Errorf("unsupported rule type %s", tp)
	}

	return parsed, parseErr
}
