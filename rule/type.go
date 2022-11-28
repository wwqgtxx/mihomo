package rules

import (
	"fmt"
	"strings"

	C "github.com/Dreamacro/clash/constant"
)

type Type struct {
	type_   C.Type
	adapter string
}

func NewType(network, adapter string) (*Type, error) {
	ntType := new(Type)
	ntType.adapter = adapter
	switch strings.ToUpper(network) {
	case "HTTP":
		ntType.type_ = C.HTTP
	case "HTTPCONNECT":
		ntType.type_ = C.HTTPCONNECT
	case "SOCKS4":
		ntType.type_ = C.SOCKS4
	case "SOCKS5":
		ntType.type_ = C.SOCKS5
	case "SHADOWSOCKS":
		ntType.type_ = C.SHADOWSOCKS
	case "REDIR":
		ntType.type_ = C.REDIR
	case "TPROXY":
		ntType.type_ = C.TPROXY
	case "TUNNEL":
		ntType.type_ = C.TUNNEL
	case "MTPROXY":
		ntType.type_ = C.MTPROXY
	case "TUN":
		ntType.type_ = C.TUN
	case "DNS":
		ntType.type_ = C.DNS
	default:
		return nil, fmt.Errorf("unsupported type")
	}

	return ntType, nil
}

func (t *Type) RuleType() C.RuleType {
	return C.Type_
}

func (t *Type) Match(metadata *C.Metadata) bool {
	return t.type_ == metadata.Type
}

func (t *Type) Adapter() string {
	return t.adapter
}

func (t *Type) Payload() string {
	return t.type_.String()
}

func (t *Type) ShouldResolveIP() bool {
	return false
}

func (t *Type) ShouldFindProcess() bool {
	return false
}
