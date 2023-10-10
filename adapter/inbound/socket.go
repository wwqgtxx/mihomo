package inbound

import (
	"net"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/transport/socks5"
)

// NewSocket receive TCP inbound and return ConnContext
func NewSocket(target socks5.Addr, conn net.Conn, source C.Type, additions ...Addition) *context.ConnContext {
	metadata := parseSocksAddr(target)
	metadata.NetWork = C.TCP
	metadata.Type = source
	additions = append(additions, WithSrcAddr(conn.RemoteAddr()), WithInAddr(conn.LocalAddr()))
	for _, addition := range additions {
		addition.Apply(metadata)
	}

	return context.NewConnContext(conn, metadata)
}
