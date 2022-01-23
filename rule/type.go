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
	case "TCPTUN":
		ntType.type_ = C.TCPTUN
	case "UDPTUN":
		ntType.type_ = C.UDPTUN
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

func (n *Type) RuleType() C.RuleType {
	return C.Type_
}

func (n *Type) Match(metadata *C.Metadata) bool {
	return n.type_ == metadata.Type
}

func (n *Type) Adapter() string {
	return n.adapter
}

func (n *Type) Payload() string {
	return n.type_.String()
}

func (n *Type) ShouldResolveIP() bool {
	return false
}
