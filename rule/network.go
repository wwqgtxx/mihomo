package rules

import (
	"fmt"
	"strings"

	C "github.com/metacubex/mihomo/constant"
)

type Network struct {
	network C.NetWork
	adapter string
}

func NewNetwork(network, adapter string) (*Network, error) {
	ntType := new(Network)
	ntType.adapter = adapter
	switch strings.ToUpper(network) {
	case "TCP":
		ntType.network = C.TCP
		break
	case "UDP":
		ntType.network = C.UDP
		break
	default:
		return nil, fmt.Errorf("unsupported network type, only TCP/UDP")
	}

	return ntType, nil
}

func (n *Network) RuleType() C.RuleType {
	return C.Network
}

func (n *Network) Match(metadata *C.Metadata) (bool, string) {
	return n.network == metadata.NetWork, n.adapter
}

func (n *Network) Adapter() string {
	return n.adapter
}

func (n *Network) Payload() string {
	return n.network.String()
}

func (n *Network) ShouldResolveIP() bool {
	return false
}

func (n *Network) ShouldFindProcess() bool {
	return false
}
