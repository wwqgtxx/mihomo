package rules

import (
	"fmt"
	"regexp"
	"strings"

	S "github.com/Dreamacro/clash/component/stack"
	C "github.com/Dreamacro/clash/constant"
)

type Logic struct {
	payload  string
	adapter  string
	ruleType C.RuleType
	rules    []C.Rule
	needIP   bool
}

func NewNOT(payload string, adapter string) (*Logic, error) {
	logic := &Logic{payload: payload, adapter: adapter, ruleType: C.NOT}
	err := logic.parsePayload(payload)
	if err != nil {
		return nil, err
	}
	logic.needIP = !logic.rules[0].ShouldResolveIP()
	return logic, nil
}

func NewOR(payload string, adapter string) (*Logic, error) {
	logic := &Logic{payload: payload, adapter: adapter, ruleType: C.OR}
	err := logic.parsePayload(payload)
	if err != nil {
		return nil, err
	}

	for _, rule := range logic.rules {
		if rule.ShouldResolveIP() {
			logic.needIP = true
			break
		}
	}

	return logic, nil
}
func NewAND(payload string, adapter string) (*Logic, error) {
	logic := &Logic{payload: payload, adapter: adapter, ruleType: C.AND}
	err := logic.parsePayload(payload)
	if err != nil {
		return nil, err
	}

	for _, rule := range logic.rules {
		if rule.ShouldResolveIP() {
			logic.needIP = true
			break
		}
	}

	return logic, nil
}

type Range struct {
	start int
	end   int
	index int
}

func (r Range) containRange(preStart, preEnd int) bool {
	return preStart < r.start && preEnd > r.end
}

func (logic *Logic) payloadToRule(subPayload string) (C.Rule, error) {
	splitStr := strings.SplitN(subPayload, ",", 2)
	tp := splitStr[0]
	payload := splitStr[1]
	if tp == "NOT" || tp == "OR" || tp == "AND" {
		return ParseRule(tp, payload, "", nil)
	}

	param := strings.Split(payload, ",")
	return ParseRule(tp, param[0], "", param[1:])
}

func (logic *Logic) format(payload string) ([]Range, error) {
	stack := S.NewStack()
	num := 0
	subRanges := make([]Range, 0)
	for i, c := range payload {
		if c == '(' {
			sr := Range{
				start: i,
				index: num,
			}

			num++
			stack.Push(sr)
		} else if c == ')' {
			sr := stack.Pop().(Range)
			sr.end = i
			subRanges = append(subRanges, sr)
		}
	}

	if stack.Len() != 0 {
		return nil, fmt.Errorf("format error is missing )")
	}

	sortResult := make([]Range, len(subRanges))
	for _, sr := range subRanges {
		sortResult[sr.index] = sr
	}

	return sortResult, nil
}

func (logic *Logic) findSubRuleRange(payload string, ruleRanges []Range) []Range {
	payloadLen := len(payload)
	subRuleRange := make([]Range, 0)
	for _, rr := range ruleRanges {
		if rr.start == 0 && rr.end == payloadLen-1 {
			// 最大范围跳过
			continue
		}

		containInSub := false
		for _, r := range subRuleRange {
			if rr.containRange(r.start, r.end) {
				// The subRuleRange contains a range of rr, which is the next level node of the tree
				containInSub = true
				break
			}
		}

		if !containInSub {
			subRuleRange = append(subRuleRange, rr)
		}
	}

	return subRuleRange
}

func (logic *Logic) parsePayload(payload string) error {
	regex, err := regexp.Compile("\\(.*\\)")
	if err != nil {
		return err
	}

	if regex.MatchString(payload) {
		subAllRanges, err := logic.format(payload)
		if err != nil {
			return err
		}
		rules := make([]C.Rule, 0, len(subAllRanges))

		subRanges := logic.findSubRuleRange(payload, subAllRanges)
		for _, subRange := range subRanges {
			subPayload := payload[subRange.start+1 : subRange.end]

			rule, err := logic.payloadToRule(subPayload)
			if err != nil {
				return err
			}

			rules = append(rules, rule)
		}

		logic.rules = rules

		return nil
	}

	return fmt.Errorf("payload format error")
}

func (logic *Logic) RuleType() C.RuleType {
	return logic.ruleType
}

func (logic *Logic) Match(metadata *C.Metadata) bool {
	switch logic.ruleType {
	case C.NOT:
		return !logic.rules[0].Match(metadata)
	case C.OR:
		for _, rule := range logic.rules {
			if rule.Match(metadata) {
				return true
			}
		}
	case C.AND:
		for _, rule := range logic.rules {
			if !rule.Match(metadata) {
				return false
			}
		}
	}
	return logic.rules[0].Match(metadata)
}

func (logic *Logic) Adapter() string {
	return logic.adapter
}

func (logic *Logic) Payload() string {
	return logic.payload
}

func (logic *Logic) ShouldResolveIP() bool {
	return logic.needIP
}
