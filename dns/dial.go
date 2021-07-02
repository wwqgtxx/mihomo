package dns

import (
	"net"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/tunnel"
)

func remoteDial(network, addr string) (net.Conn, error) {
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
	metadata.Type = C.DNS
	connContext := context.NewConnContext(conn2, metadata)
	tunnel.TCPIn() <- connContext

	return conn1, nil
}
