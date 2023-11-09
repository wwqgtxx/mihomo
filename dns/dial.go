package dns

import (
	"context"
	"net"

	"github.com/metacubex/mihomo/component/inner_dialer"
	C "github.com/metacubex/mihomo/constant"
)

var remoteDialer = inner_dialer.NewDialer(C.DNS)

func remoteDial(network, addr string) (net.Conn, error) {
	return remoteDialer.DialContext(context.Background(), network, addr)
}
