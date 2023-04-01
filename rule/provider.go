package rules

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"runtime"
	"strings"
	"time"

	"github.com/Dreamacro/clash/adapter/provider"
	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/common/structure"
	C "github.com/Dreamacro/clash/constant"
	providerTypes "github.com/Dreamacro/clash/constant/provider"
)

// RuleProvider interface
type RuleProvider interface {
	providerTypes.Provider
	Rules() []C.Rule
}

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
	behavior  string
	ruleCount int
}

func (rp *ruleSetProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"name":        rp.Name(),
		"type":        rp.Type().String(),
		"vehicleType": rp.VehicleType().String(),
		"behavior":    rp.behavior,
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

func (rp *ruleSetProvider) Initial() error {
	elm, err := rp.Fetcher.Initial()
	if err != nil {
		return err
	}

	rp.Fetcher.OnUpdate()(elm)
	return nil
}

func (rp *ruleSetProvider) Type() providerTypes.ProviderType {
	return providerTypes.Rule
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

func rulesParse(buf []byte, behavior string) (any, error) {
	printMemStats("before")
	schema := &RuleSchema{}

	reader := bufio.NewReader(bytes.NewReader(buf))

	firstLineBuffer := pool.GetBuffer()
	defer pool.PutBuffer(firstLineBuffer)
	firstLineLength := 0

	var rules []C.Rule
	var rt RuleTree

	for {
		line, isPrefix, err := reader.ReadLine()
		if err != nil {
			if err == io.EOF {
				if firstLineLength == 0 { // find payload head
					return nil, ErrNoPayload
				}
				break
			}
			return nil, err
		}
		firstLineBuffer.Write(line) // need a copy because the returned buffer is only valid until the next call to ReadLine
		if isPrefix {
			// If the line was too long for the buffer then isPrefix is set and the
			// beginning of the line is returned. The rest of the line will be returned
			// from future calls.
			continue
		}
		if firstLineLength == 0 { // find payload head
			firstLineBuffer.WriteByte('\n')
			firstLineLength = firstLineBuffer.Len()
			firstLineBuffer.WriteString("  - ''") // a test line

			err = yaml.Unmarshal(firstLineBuffer.Bytes(), schema)
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
		err = yaml.Unmarshal(firstLineBuffer.Bytes(), schema)
		firstLineBuffer.Truncate(firstLineLength)
		if err != nil {
			continue
		}
		var str string
		if len(schema.Payload) > 0 {
			str = schema.Payload[0]
		}
		if len(schema.Rules) > 0 {
			str = schema.Rules[0]
		}
		if str == "" {
			continue
		}

		switch behavior {
		case "domain":
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
		case "ipcidr":
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
	if rp.ruleCount == 1 && rp.behavior != "classical" {
		if rt, ok := rp.rules[0].(RuleTree); ok {
			rp.ruleCount = rt.RuleCount()
		}
	}
}

func stopRuleProvider(rd *RuleSetProvider) {
	rd.Fetcher.Destroy()
}

func NewRuleSetProvider(name string, interval time.Duration, vehicle providerTypes.Vehicle, behavior string) *RuleSetProvider {
	rp := &ruleSetProvider{
		rules:    []C.Rule{},
		behavior: behavior,
	}

	onUpdate := func(elm any) {
		ret := elm.([]C.Rule)
		rp.setRules(ret)
	}

	parse := func(bytes []byte) (any, error) { return rulesParse(bytes, rp.behavior) }

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
	Interval int    `provider:"interval,omitempty"`
}

func ParseRuleProvider(name string, mapping map[string]any) (RuleProvider, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})

	schema := &ruleProviderSchema{}
	if err := decoder.Decode(mapping, schema); err != nil {
		return nil, err
	}

	path := C.Path.Resolve(schema.Path)

	var vehicle providerTypes.Vehicle
	switch schema.Type {
	case "file":
		vehicle = provider.NewFileVehicle(path)
	case "http":
		vehicle = provider.NewHTTPVehicle(schema.URL, path)
	default:
		return nil, fmt.Errorf("%w: %s", provider.ErrVehicleType, schema.Type)
	}

	behavior := schema.Behavior

	interval := time.Duration(uint(schema.Interval)) * time.Second
	return NewRuleSetProvider(name, interval, vehicle, behavior), nil
}
