package obfs

import "net"

type plain struct{}

func init() {
	register("plain", newPlain, 0)
}

func newPlain(b *Base) Obfs {
	return &plain{}
}

func (p *plain) Decode(b []byte) ([]byte, bool, error) { return b, false, nil }

func (p *plain) Encode(buf, b []byte) ([]byte, error) { return b, nil }

func (p *plain) StreamConn(c net.Conn) net.Conn { return c }
