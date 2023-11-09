package rules

import (
	"strings"

	"github.com/metacubex/mihomo/component/mmdb"
	C "github.com/metacubex/mihomo/constant"
)

type GEOIP struct {
	country     string
	adapter     string
	noResolveIP bool
}

func (g *GEOIP) RuleType() C.RuleType {
	return C.GEOIP
}

func (g *GEOIP) Match(metadata *C.Metadata) (bool, string) {
	ip := metadata.DstIP
	if !ip.IsValid() {
		return false, ""
	}

	if strings.EqualFold(g.country, "LAN") {
		return ip.IsPrivate(), g.adapter
	}
	record, _ := mmdb.Instance().Country(ip.AsSlice())
	return strings.EqualFold(record.Country.IsoCode, g.country), g.adapter
}

func (g *GEOIP) Adapter() string {
	return g.adapter
}

func (g *GEOIP) Payload() string {
	return g.country
}

func (g *GEOIP) ShouldResolveIP() bool {
	return !g.noResolveIP
}

func (g *GEOIP) ShouldFindProcess() bool {
	return false
}

func NewGEOIP(country string, adapter string, noResolveIP bool) *GEOIP {
	geoip := &GEOIP{
		country:     country,
		adapter:     adapter,
		noResolveIP: noResolveIP,
	}

	return geoip
}
