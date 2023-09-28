package inner_dialer

import (
	"context"
	"net"
	"strconv"

	C "github.com/Dreamacro/clash/constant"
	icontext "github.com/Dreamacro/clash/context"
)

var tunnel C.Tunnel

func Init(t C.Tunnel) {
	tunnel = t
}

type RemoteDialer struct {
	mType C.Type
}

func NewDialer(mType C.Type) *RemoteDialer {
	return &RemoteDialer{mType: mType}
}

func (d RemoteDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.DialTCP(addr, "")
}

func (d RemoteDialer) DialTCP(addr string, proxyName string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	uintPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, err
	}

	conn1, conn2 := net.Pipe()
	metadata := &C.Metadata{
		NetWork:      C.TCP,
		Host:         host,
		DstPort:      uint16(uintPort),
		SpecialProxy: proxyName,
	}
	metadata.Type = d.mType
	connContext := icontext.NewConnContext(conn2, metadata)
	go tunnel.HandleTCPConn(connContext)

	return conn1, nil
}
