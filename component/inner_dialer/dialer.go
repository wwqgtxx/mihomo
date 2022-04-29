package inner_dialer

import (
	"context"
	"net"

	"github.com/Dreamacro/clash/adapter/inbound"
	C "github.com/Dreamacro/clash/constant"
	icontext "github.com/Dreamacro/clash/context"
)

var tcpIn chan<- C.ConnContext
var udpIn chan<- *inbound.PacketAdapter

func Init(tcp chan<- C.ConnContext, udp chan<- *inbound.PacketAdapter) {
	tcpIn = tcp
	udpIn = udp
}

type RemoteDialer struct {
	mType C.Type
}

func NewDialer(mType C.Type) *RemoteDialer {
	return &RemoteDialer{mType: mType}
}

func (d RemoteDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	conn1, conn2 := net.Pipe()
	metadata := &C.Metadata{
		NetWork:  C.TCP,
		AddrType: C.AtypDomainName,
		Host:     host,
		DstIP:    nil,
		DstPort:  port,
	}
	metadata.Type = d.mType
	connContext := icontext.NewConnContext(conn2, metadata)
	tcpIn <- connContext

	return conn1, nil
}
