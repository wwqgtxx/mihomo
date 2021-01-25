package protocol

import (
	"net"

	"github.com/Dreamacro/clash/common/pool"
)

type PacketConn struct {
	net.PacketConn
	Protocol
}

func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	buf := pool.Get(64 * 1024)
	defer pool.Put(buf)
	encoded, err := c.EncodePacket(buf[:0], b)
	if err != nil {
		return 0, err
	}
	_, err = c.PacketConn.WriteTo(encoded, addr)
	return len(b), err
}

func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}
	decoded, err := c.DecodePacket(b[:n])
	if err != nil {
		return n, addr, err
	}
	copy(b, decoded)
	return len(decoded), addr, nil
}
