package provider

import (
	"errors"
	"fmt"
	"time"

	"github.com/Dreamacro/clash/common/structure"
	C "github.com/Dreamacro/clash/constant"
	types "github.com/Dreamacro/clash/constant/provider"
)

var (
	ErrVehicleType = errors.New("unsupport vehicle type")
)

type healthCheckSchema struct {
	Enable   bool   `provider:"enable"`
	URL      string `provider:"url"`
	Interval int    `provider:"interval"`
	Lazy     bool   `provider:"lazy,omitempty"`
	Type     string `provider:"type"`
}

type proxyProviderSchema struct {
	Type        string            `provider:"type"`
	Path        string            `provider:"path"`
	URL         string            `provider:"url,omitempty"`
	Interval    int               `provider:"interval,omitempty"`
	Filter      string            `provider:"filter,omitempty"`
	HealthCheck healthCheckSchema `provider:"health-check,omitempty"`
}

func ParseProxyProvider(name string, mapping map[string]interface{}) (types.ProxyProvider, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})

	schema := &proxyProviderSchema{
		HealthCheck: healthCheckSchema{
			Lazy: HealthCheckLazyDefault(),
		},
	}
	if err := decoder.Decode(mapping, schema); err != nil {
		return nil, err
	}

	var hcInterval uint
	if schema.HealthCheck.Enable {
		hcInterval = uint(schema.HealthCheck.Interval)
	}
	hc := NewHealthCheck([]C.Proxy{}, schema.HealthCheck.URL, hcInterval, schema.HealthCheck.Lazy, schema.HealthCheck.Type)

	path := C.Path.Resolve(schema.Path)

	var vehicle types.Vehicle
	switch schema.Type {
	case "file":
		vehicle = NewFileVehicle(path)
	case "http":
		vehicle = NewHTTPVehicle(schema.URL, path)
	default:
		return nil, fmt.Errorf("%w: %s", ErrVehicleType, schema.Type)
	}

	interval := time.Duration(uint(schema.Interval)) * time.Second
	filter := schema.Filter
	return NewProxySetProvider(name, interval, filter, vehicle, hc)
}
