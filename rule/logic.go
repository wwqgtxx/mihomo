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

func (logic *Logic) parsePayload(payload string) error {
	type Range struct {
		start int
		end   int
		index int
	}

	regex, err := regexp.Compile("\\(.*\\)")
	if err != nil {
		return err
	}

	if regex.MatchString(payload) {
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
			return fmt.Errorf("format error is missing )")
		}

		sortResult := make([]Range, len(subRanges))
		for _, sr := range subRanges {
			sortResult[sr.index] = sr
		}
		subRanges = sortResult

		if err != nil {
			return err
		}
		rules := make([]C.Rule, 0, len(subRanges))

		if len(subRanges) == 1 {
			subPayload := payload[subRanges[0].start+1 : subRanges[0].end-1]
			rule, err := logic.payloadToRule(subPayload)
			if err != nil {
				return err
			}

			rules = append(rules, rule)
		} else {
			preStart := subRanges[0].start
			preEnd := subRanges[0].end
			for _, sr := range subRanges[1:] {
				if preStart < sr.start && preEnd > sr.end && sr.start-preStart > 1 {
					str := ""
					if preStart+1 <= sr.start-1 {
						str = strings.TrimSpace(payload[preStart+1 : sr.start-1])
					}

					if str == "AND" || str == "OR" || str == "NOT" {
						subPayload := payload[preStart+1 : preEnd]
						rule, err := logic.payloadToRule(subPayload)
						if err != nil {
							return err
						}

						rules = append(rules, rule)
						preStart = sr.start
						preEnd = sr.end
					}

					continue
				}

				preStart = sr.start
				preEnd = sr.end

				subPayload := payload[sr.start+1 : sr.end]
				rule, err := logic.payloadToRule(subPayload)
				if err != nil {
					return err
				}

				rules = append(rules, rule)
			}
		}

		if len(rules) < 1 {
			return fmt.Errorf("the parsed rule is empty")
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
