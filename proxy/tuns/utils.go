package tuns

import (
	"errors"
	"net"
	"strings"

	"github.com/wwqgtxx/clashr/common/pool"
)

type PairList [][2]string // key1=val1,key2=val2,...

func (l PairList) String() string {
	s := make([]string, len(l))
	for i, pair := range l {
		s[i] = pair[0] + "=" + pair[1]
	}
	return strings.Join(s, ",")
}
func (l *PairList) Set(s string) error {
	for _, item := range strings.Split(s, ",") {
		pair := strings.Split(item, "=")
		if len(pair) != 2 {
			return nil
		}
		*l = append(*l, [2]string{pair[0], pair[1]})
	}
	return nil
}

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
	packet := b
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
