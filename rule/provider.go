package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"runtime"
	"strings"
	"time"

	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type RuleSchema struct {
	Payload []string `yaml:"payload"`
	Rules   []string `yaml:"rules"`
}

// for auto gc
type RuleSetProvider struct {
	*ruleSetProvider
}

type ruleSetProvider struct {
	*provider.Fetcher
	rules     []C.Rule
	behavior  P.RuleBehavior
	format    P.RuleFormat
	ruleCount int
}

func (rp *ruleSetProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"name":        rp.Name(),
		"type":        rp.Type().String(),
		"vehicleType": rp.VehicleType().String(),
		"behavior":    rp.behavior.String(),
		"format":      rp.format.String(),
		"ruleCount":   rp.ruleCount,
		"updatedAt":   rp.UpdateAt(),
	})
}

func (rp *ruleSetProvider) Name() string {
	return rp.Fetcher.Name()
}

func (rp *ruleSetProvider) Update() error {
	elm, same, err := rp.Fetcher.Update()
	if err == nil && !same {
		rp.Fetcher.OnUpdate()(elm)
	}
	return err
}

func (rp *ruleSetProvider) Behavior() P.RuleBehavior {
	return rp.behavior
}

func (rp *ruleSetProvider) Initial() error {
	elm, err := rp.Fetcher.Initial()
	if err != nil {
		return err
	}

	rp.Fetcher.OnUpdate()(elm)
	return nil
}

func (rp *ruleSetProvider) Type() P.ProviderType {
	return P.Rule
}

func (rp *ruleSetProvider) Rules() []C.Rule {
	return rp.rules
}

type RuleTree interface {
	C.Rule
	RuleCount() int
	Insert(string) error
	FinishInsert()
}

var ErrNoPayload = errors.New("file must have a `payload` field")

func rulesParse(buf []byte, behavior P.RuleBehavior, format P.RuleFormat) (any, error) {
	printMemStats("before")
	schema := &RuleSchema{}

	firstLineBuffer := pool.GetBuffer()
	defer pool.PutBuffer(firstLineBuffer)
	firstLineLength := 0

	var rules []C.Rule
	var rt RuleTree

	s := 0 // search start index
	for s < len(buf) {
		// search buffer for a new line.
		line := buf[s:]
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			i += s
			line = buf[s : i+1]
			s = i + 1
		} else {
			s = len(buf)              // stop loop in next step
			if firstLineLength == 0 { // no head or only one line body
				return nil, ErrNoPayload
			}
		}
		var str string
		switch format {
		case P.TextRule:
			firstLineLength = -1 // don't return ErrNoPayload when read last line
			str = string(line)
			str = strings.TrimSpace(str)
			if len(str) == 0 {
				continue
			}
			if str[0] == '#' { // comment
				continue
			}
			if strings.HasPrefix(str, "//") { // comment in Premium core
				continue
			}
		case P.YamlRule:
			trimLine := bytes.TrimSpace(line)
			if len(trimLine) == 0 {
				continue
			}
			if trimLine[0] == '#' { // comment
				continue
			}
			firstLineBuffer.Write(line)
			if firstLineLength == 0 { // find payload head
				firstLineLength = firstLineBuffer.Len()
				firstLineBuffer.WriteString("  - ''") // a test line

				err := yaml.Unmarshal(firstLineBuffer.Bytes(), schema)
				firstLineBuffer.Truncate(firstLineLength)
				if err == nil && (len(schema.Payload) > 0 || len(schema.Rules) > 0) { // found
					continue
				}

				// not found or err!=nil
				firstLineBuffer.Truncate(0)
				firstLineLength = 0
				continue
			}

			// parse payload body
			err := yaml.Unmarshal(firstLineBuffer.Bytes(), schema)
			firstLineBuffer.Truncate(firstLineLength)
			if err != nil {
				continue
			}
			if len(schema.Payload) > 0 {
				str = schema.Payload[0]
			}
			if len(schema.Rules) > 0 {
				str = schema.Rules[0]
			}
		}

		if str == "" {
			continue
		}

		switch behavior {
		case P.Domain:
			if rt == nil {
				rt = NewDomainTree()
			}
			err := rt.Insert(str)
			if err != nil {
				return nil, fmt.Errorf("rule '%s' error: %w", str, err)
			}
			if rules == nil {
				rules = []C.Rule{rt}
			}
		case P.IPCIDR:
			if rt == nil {
				rt = NewIPCIDRTree()
			}
			err := rt.Insert(str)
			if err != nil {
				return nil, fmt.Errorf("rule '%s' error: %w", str, err)
			}
			if rules == nil {
				rules = []C.Rule{rt}
			}
		default: // classical
			line := str

			var rule []string
			var payload string
			var params []string

			rule = trimArr(strings.Split(line, ","))
			ruleName := rule[0]
			if ruleName == "NOT" || ruleName == "OR" || ruleName == "AND" {
				payload = strings.Join(rule[1:len(rule)-1], ",")
			} else {
				switch l := len(rule); {
				case l == 2:
					payload = rule[1]
				case l >= 3:
					payload = rule[1]
					params = rule[2:]
				default:
					return nil, fmt.Errorf("rules[%s] error: format invalid", line)
				}
			}
			rule = trimArr(rule)
			params = trimArr(params)
			parsed, err := ParseRule(rule[0], payload, "", params, nil)
			if err != nil {
				return nil, fmt.Errorf("rule '%s' error: %w", str, err)
			}
			rules = append(rules, parsed)
		}
	}

	if rt != nil {
		rt.FinishInsert()
	}

	if len(rules) == 0 {
		return nil, errors.New("file doesn't have any valid rule")
	}

	printMemStats("after")
	return rules, nil
}

func printMemStats(mag string) {
	var m runtime.MemStats
	//runtime.GC()
	runtime.ReadMemStats(&m)
	fmt.Printf("%v：memory = %vKB, GC Times = %v\n", mag, m.Alloc/1024, m.NumGC)
}

func (rp *ruleSetProvider) setRules(rules []C.Rule) {
	rp.rules = rules
	rp.ruleCount = len(rp.rules)
	if rp.ruleCount == 1 && rp.behavior != P.Classical {
		if rt, ok := rp.rules[0].(RuleTree); ok {
			rp.ruleCount = rt.RuleCount()
		}
	}
}

func stopRuleProvider(rd *RuleSetProvider) {
	rd.Fetcher.Destroy()
}

func NewRuleSetProvider(name string, interval time.Duration, vehicle P.Vehicle, behavior P.RuleBehavior, format P.RuleFormat) *RuleSetProvider {
	rp := &ruleSetProvider{
		rules:    []C.Rule{},
		behavior: behavior,
		format:   format,
	}

	onUpdate := func(elm any) {
		ret := elm.([]C.Rule)
		rp.setRules(ret)
	}

	parse := func(bytes []byte) (any, error) { return rulesParse(bytes, behavior, format) }

	fetcher := provider.NewFetcher(name, interval, vehicle, parse, onUpdate)
	rp.Fetcher = fetcher

	wrapper := &RuleSetProvider{rp}
	runtime.SetFinalizer(wrapper, stopRuleProvider)
	return wrapper
}

type ruleProviderSchema struct {
	Behavior string `provider:"behavior"`
	Type     string `provider:"type"`
	Path     string `provider:"path"`
	URL      string `provider:"url,omitempty"`
	Format   string `provider:"format,omitempty"`
	Interval int    `provider:"interval,omitempty"`
}

func ParseRuleProvider(name string, mapping map[string]any) (P.RuleProvider, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})

	schema := &ruleProviderSchema{}
	if err := decoder.Decode(mapping, schema); err != nil {
		return nil, err
	}

	var behavior P.RuleBehavior

	switch schema.Behavior {
	case "domain":
		behavior = P.Domain
	case "ipcidr":
		behavior = P.IPCIDR
	case "classical":
		behavior = P.Classical
	default:
		return nil, fmt.Errorf("unsupported behavior type: %s", schema.Behavior)
	}

	var format P.RuleFormat

	switch schema.Format {
	case "", "yaml":
		format = P.YamlRule
	case "text":
		format = P.TextRule
	default:
		return nil, fmt.Errorf("unsupported format type: %s", schema.Format)
	}

	path := C.Path.Resolve(schema.Path)

	var vehicle P.Vehicle
	switch schema.Type {
	case "file":
		vehicle = provider.NewFileVehicle(path)
	case "http":
		vehicle = provider.NewHTTPVehicle(schema.URL, path)
	default:
		return nil, fmt.Errorf("%w: %s", provider.ErrVehicleType, schema.Type)
	}

	interval := time.Duration(uint(schema.Interval)) * time.Second
	return NewRuleSetProvider(name, interval, vehicle, behavior, format), nil
}
