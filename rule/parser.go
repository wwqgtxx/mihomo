package rules

import (
	"fmt"
	"strings"

	C "github.com/metacubex/mihomo/constant"
)

func trimArr(arr []string) (r []string) {
	for _, e := range arr {
		r = append(r, strings.Trim(e, " "))
	}
	return
}

func ParseRule(tp, payload, target string, params []string, subRules map[string][]C.Rule) (C.Rule, error) {
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
		parsed, parseErr = NewProcess(payload, target, true, false)
	case "PROCESS-PATH":
		parsed, parseErr = NewProcess(payload, target, false, false)
	case "PROCESS-NAME-REGEX":
		parsed, parseErr = NewProcess(payload, target, true, true)
	case "PROCESS-PATH-REGEX":
		parsed, parseErr = NewProcess(payload, target, false, true)
	case "NETWORK":
		parsed, parseErr = NewNetwork(payload, target)
	case "IN-TYPE":
		parsed, parseErr = NewInType(payload, target)
	case "IN-USER":
		parsed, parseErr = NewInUser(payload, target)
	case "IN-NAME":
		parsed, parseErr = NewInName(payload, target)
	case "IPSET":
		noResolve := HasNoResolve(params)
		parsed, parseErr = NewIPSet(payload, target, noResolve)
	case "MATCH":
		parsed = NewMatch(target)
	case "RULE-SET":
		if target == "" {
			// don't allow use RULE-SET in a Rule Providers' classical config file
			// and also don't allow use RULE-SET in NOT/AND/OR logic
			parseErr = fmt.Errorf("unsupported rule type %s", tp)
			break
		}
		parsed = NewRuleSet(payload, target)
	case "SUB-RULE":
		parsed, parseErr = NewSubRule(payload, target, subRules, ParseRule)
	case "NOT":
		parsed, parseErr = NewNOT(payload, target, ParseRule)
	case "AND":
		parsed, parseErr = NewAND(payload, target, ParseRule)
	case "OR":
		parsed, parseErr = NewOR(payload, target, ParseRule)
	default:
		parseErr = fmt.Errorf("unsupported rule type %s", tp)
	}

	return parsed, parseErr
}
