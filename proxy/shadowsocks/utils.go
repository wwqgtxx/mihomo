package shadowsocks

import (
	"bytes"
	"errors"
	"net"

	"github.com/wwqgtxx/clashr/common/pool"
	"github.com/wwqgtxx/clashr/component/socks5"
)

type fakeConn struct {
	net.PacketConn
	rAddr   net.Addr
	payload []byte
	bufRef  []byte
}

func (c *fakeConn) Data() []byte {
	return c.payload
}

// WriteBack wirtes UDP packet with source(ip, port) = `addr`
func (c *fakeConn) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	if addr == nil {
		err = errors.New("address is invalid")
		return
	}
	packet := bytes.Join([][]byte{socks5.ParseAddrToSocksAddr(addr), b}, []byte{})
	return c.PacketConn.WriteTo(packet, c.rAddr)
}

// LocalAddr returns the source IP/Port of UDP Packet
func (c *fakeConn) LocalAddr() net.Addr {
	return c.rAddr
}

func (c *fakeConn) Close() error {
	err := c.PacketConn.Close()
	pool.BufPool.Put(c.bufRef[:cap(c.bufRef)])
	return err
}
