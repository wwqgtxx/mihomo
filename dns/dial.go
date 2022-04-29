package dns

import (
	"context"
	"net"

	"github.com/Dreamacro/clash/component/inner_dialer"
	C "github.com/Dreamacro/clash/constant"
)

var remoteDialer = inner_dialer.NewDialer(C.DNS)

func remoteDial(network, addr string) (net.Conn, error) {
	return remoteDialer.DialContext(context.Background(), network, addr)
}
