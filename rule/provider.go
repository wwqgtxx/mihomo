package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Dreamacro/clash/adapter/provider"
	"github.com/Dreamacro/clash/common/structure"
	C "github.com/Dreamacro/clash/constant"
	"gopkg.in/yaml.v2"
	"runtime"
	"time"
)

// RuleProvider interface
type RuleProvider interface {
	provider.Provider
	Rules() []C.Rule
}

type RuleSchema struct {
	Payload []string `yaml:"payload"`
}

// for auto gc
type RuleSetProvider struct {
	*ruleSetProvider
}

type ruleSetProvider struct {
	*provider.Fetcher
	rules    []C.Rule
	behavior string
}

func (rp *ruleSetProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"name":        rp.Name(),
		"type":        rp.Type().String(),
		"vehicleType": rp.VehicleType().String(),
		"behavior":    rp.behavior,
		"ruleCount":   len(rp.rules),
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

func (rp *ruleSetProvider) Type() provider.ProviderType {
	return provider.Rule
}

func (rp *ruleSetProvider) Rules() []C.Rule {
	return rp.rules
}

func rulesParse(buf []byte, behavior string) (interface{}, error) {
	schema := &RuleSchema{}

	if err := yaml.Unmarshal(buf, schema); err != nil {
		return nil, err
	}

	if schema.Payload == nil {
		return nil, errors.New("file must have a `payload` field")
	}

	rules := []C.Rule{}
	for idx, str := range schema.Payload {
		rule, err := parseProviderRule(str, behavior)
		if err != nil {
			return nil, fmt.Errorf("rule %d error: %w", idx, err)
		}
		rules = append(rules, rule)
	}

	if len(rules) == 0 {
		return nil, errors.New("file doesn't have any valid proxy")
	}

	return rules, nil
}

func (rp *ruleSetProvider) setRules(rules []C.Rule) {
	rp.rules = rules
}

func stopRuleProvider(rd *RuleSetProvider) {
	rd.Fetcher.Destroy()
}

func NewRuleSetProvider(name string, interval time.Duration, vehicle provider.Vehicle, behavior string) *RuleSetProvider {

	rd := &ruleSetProvider{
		rules:    []C.Rule{},
		behavior: behavior,
	}

	onUpdate := func(elm interface{}) {
		ret := elm.([]C.Rule)
		rd.setRules(ret)
	}

	parse := func(bytes []byte) (interface{}, error) { return rulesParse(bytes, behavior) }

	fetcher := provider.NewFetcher(name, interval, vehicle, parse, onUpdate)
	rd.Fetcher = fetcher

	wrapper := &RuleSetProvider{rd}
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

func ParseRuleProvider(name string, mapping map[string]interface{}) (RuleProvider, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})

	schema := &ruleProviderSchema{}
	if err := decoder.Decode(mapping, schema); err != nil {
		return nil, err
	}

	path := C.Path.Resolve(schema.Path)

	var vehicle provider.Vehicle
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
