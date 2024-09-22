package provider

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	types "github.com/metacubex/mihomo/constant/provider"
)

var (
	ErrVehicleType = errors.New("unsupport vehicle type")
	errSubPath     = errors.New("path is not subpath of home directory")
)

type healthCheckSchema struct {
	Enable   bool   `provider:"enable"`
	URL      string `provider:"url"`
	Interval int    `provider:"interval"`
	Lazy     bool   `provider:"lazy,omitempty"`
	Type     string `provider:"type"`
}

type proxyProviderSchema struct {
	Type          string              `provider:"type"`
	Path          string              `provider:"path"`
	URL           string              `provider:"url,omitempty"`
	Proxy         string              `provider:"proxy,omitempty"`
	ConverterURL  string              `provider:"converter-url,omitempty"`
	Interval      int                 `provider:"interval,omitempty"`
	Filter        string              `provider:"filter,omitempty"`
	ExcludeFilter string              `provider:"exclude-filter,omitempty"`
	DialerProxy   string              `provider:"dialer-proxy,omitempty"`
	HealthCheck   healthCheckSchema   `provider:"health-check,omitempty"`
	Header        map[string][]string `provider:"header,omitempty"`
}

func ParseProxyProvider(name string, mapping map[string]any, healthCheckLazyDefault bool, healthCheckURL string) (types.ProxyProvider, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})

	schema := &proxyProviderSchema{
		HealthCheck: healthCheckSchema{
			Lazy: healthCheckLazyDefault,
			URL:  healthCheckURL,
		},
	}
	if err := decoder.Decode(mapping, schema); err != nil {
		return nil, err
	}

	var hcInterval uint
	if schema.HealthCheck.Enable {
		hcInterval = uint(schema.HealthCheck.Interval)
	}
	hc := NewHealthCheck([]C.Proxy{}, schema.HealthCheck.URL, hcInterval, schema.HealthCheck.Lazy, schema.HealthCheck.Type, name)

	if len(schema.ConverterURL) > 0 {
		schema.URL = strings.Replace(schema.ConverterURL, "{url}", url.QueryEscape(schema.URL), 1)
	}

	var vehicle types.Vehicle
	switch schema.Type {
	case "file":
		path := C.Path.Resolve(schema.Path)
		vehicle = resource.NewFileVehicle(path)
	case "http":
		path := C.Path.GetPathByHash("proxies", schema.URL)
		if schema.Path != "" {
			path = C.Path.Resolve(schema.Path)
			if !C.Path.IsSafePath(path) {
				return nil, fmt.Errorf("%w: %s", errSubPath, path)
			}
		}
		vehicle = resource.NewHTTPVehicle(schema.URL, path, schema.Proxy, schema.Header, resource.DefaultHttpTimeout)
	default:
		return nil, fmt.Errorf("%w: %s", ErrVehicleType, schema.Type)
	}

	interval := time.Duration(uint(schema.Interval)) * time.Second
	filter := schema.Filter
	excludeFilter := schema.ExcludeFilter
	dialerProxy := schema.DialerProxy
	return NewProxySetProvider(name, interval, filter, excludeFilter, dialerProxy, vehicle, hc)
}
