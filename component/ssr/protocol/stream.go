package protocol

import (
	"net"

	"github.com/Dreamacro/clash/common/pool"
)

type Conn struct {
	net.Conn
	Protocol
	buf    []byte
	offset int
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.buf != nil {
		n := copy(b, c.buf[c.offset:])
		c.offset += n
		if c.offset == len(c.buf) {
			pool.Put(c.buf)
			c.buf = nil
		}
		return n, nil
	}

	buf := pool.Get(pool.RelayBufferSize)
	defer pool.Put(buf)
	n, err := c.Conn.Read(buf)
	if err != nil {
		return 0, err
	}
	decoded, err := c.Decode(buf[:n])
	if err != nil {
		return 0, err
	}
	decodedData := pool.Get(len(decoded))
	copy(decodedData, decoded)
	n = copy(b, decodedData)
	if len(decodedData) > n {
		c.buf = decodedData
		c.offset = n
	} else {
		pool.Put(decodedData)
	}
	return n, nil
}

func (c *Conn) Write(b []byte) (int, error) {
	bLength := len(b)
	buf := pool.Get(pool.RelayBufferSize)
	defer pool.Put(buf)
	encoded, err := c.Encode(buf[:0], b)
	if err != nil {
		return 0, err
	}
	_, err = c.Conn.Write(encoded)
	if err != nil {
		return 0, err
	}
	return bLength, nil
}
