package inbound

import (
	"net"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/transport/socks5"
)

// NewSocket receive TCP inbound and return ConnContext
func NewSocket(target socks5.Addr, conn net.Conn, source C.Type) *context.ConnContext {
	metadata := parseSocksAddr(target)
	metadata.NetWork = C.TCP
	metadata.Type = source
	remoteAddr := conn.RemoteAddr()
	// Filter when net.Addr interface is nil
	if remoteAddr != nil {
		if ip, port, err := parseAddr(remoteAddr.String()); err == nil {
			metadata.SrcIP = ip
			metadata.SrcPort = port
		}
	}
	localAddr := conn.LocalAddr()
	// Filter when net.Addr interface is nil
	if localAddr != nil {
		if ip, port, err := parseAddr(conn.LocalAddr().String()); err == nil {
			metadata.InIP = ip
			metadata.InPort = port
		}
	}

	return context.NewConnContext(conn, metadata)
}
