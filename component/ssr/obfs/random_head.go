package obfs

import (
	"hash/crc32"
	"math/rand"
	"net"

	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/component/ssr/tools"
)

func init() {
	register("random_head", newRandomHead, 0)
}

type randomHead struct {
	*Base
	hasSentHeader bool
	rawTransSent  bool
	rawTransRecv  bool
	buf           []byte
}

func newRandomHead(b *Base) Obfs {
	return &randomHead{Base: b}
}

func (r *randomHead) StreamConn(c net.Conn) net.Conn {
	o := &randomHead{Base: r.Base}
	return &Conn{Conn: c, Obfs: o}
}

func (r *randomHead) Decode(b []byte) ([]byte, bool, error) {
	if r.rawTransRecv {
		return b, false, nil
	}
	r.rawTransRecv = true
	return nil, true, nil
}

func (r *randomHead) Encode(buf, b []byte) ([]byte, error) {
	if r.rawTransSent {
		return b, nil
	}
	if r.buf == nil {
		if len(b) == 0 {
			return b, nil
		}
		r.buf = pool.Get(pool.RelayBufferSize)[:0]
	}
	r.buf = append(r.buf, b...)
	if !r.hasSentHeader {
		r.hasSentHeader = true
		dataLength := rand.Intn(96) + 4
		buf = tools.AppendRandBytes(buf, dataLength)
		crc := (0xffffffff - crc32.ChecksumIEEE(buf)) & 0xffffffff
		return tools.AppendUint32LittleEndian(buf, crc), nil
	}
	if r.rawTransRecv {
		buf = append(buf, r.buf...)
		pool.Put(r.buf)
		r.rawTransSent = true
		return buf, nil
	}
	return nil, nil
}
