package obfs

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/component/ssr/tools"
)

func init() {
	register("tls1.2_ticket_auth", newTLS12Ticket, 5)
	register("tls1.2_ticket_fastauth", newTLS12Ticket, 5)
}

type tls12Ticket struct {
	*Base
	*authData
	handshakeStatus int
	sendBuf         []byte
	recvBuf         []byte
	recvOffset      int
	ticketBuf       map[string][]byte
}

func newTLS12Ticket(b *Base) Obfs {
	r := &tls12Ticket{Base: b, authData: &authData{}}
	rand.Read(r.clientID[:])
	return r
}

func (t *tls12Ticket) StreamConn(c net.Conn) net.Conn {
	o := &tls12Ticket{Base: t.Base, authData: t.authData}
	o.clientID = t.clientID
	o.ticketBuf = make(map[string][]byte)
	return &Conn{Conn: c, Obfs: o}
}

func (t *tls12Ticket) Decode(b []byte) ([]byte, bool, error) {
	if t.handshakeStatus == 8 {
		if len(t.recvBuf) == 0 {
			if len(b) == 0 {
				return b, false, nil
			}
			t.recvBuf = pool.Get(pool.RelayBufferSize)[:0]
		}
		t.recvBuf = append(t.recvBuf, b...)
		b = b[:0]
		for len(t.recvBuf)-t.recvOffset > 5 {
			if !bytes.Equal(t.recvBuf[t.recvOffset:3+t.recvOffset], []byte{0x17, 3, 3}) {
				return []byte{}, false, errTLS12TicketAuthIncorrectMagicNumber
			}
			size := int(binary.BigEndian.Uint16(t.recvBuf[3+t.recvOffset : 5+t.recvOffset]))
			if len(t.recvBuf) < size+5+t.recvOffset {
				break
			}
			b = append(b, t.recvBuf[5+t.recvOffset:5+size+t.recvOffset]...)
			t.recvOffset += 5 + size
			if len(t.recvBuf) == t.recvOffset {
				pool.Put(t.recvBuf)
				t.recvBuf = nil
				t.recvOffset = 0
			}
		}
		return b, false, nil
	}

	if len(b) < 11+32+1+32 {
		return []byte{}, false, errTLS12TicketAuthTooShortData
	}

	if !hmac.Equal(b[33:33+10], t.hmacSHA1(b[11:33])[:10]) {
		return []byte{}, false, errTLS12TicketAuthHMACError
	}

	if !hmac.Equal(b[len(b)-10:], t.hmacSHA1(b[:len(b)-10])[:10]) {
		return []byte{}, false, errTLS12TicketAuthHMACError
	}

	return []byte{}, true, nil
}

func (t *tls12Ticket) Encode(buf, b []byte) ([]byte, error) {
	if t.handshakeStatus == 8 {
		offset := 0
		for len(b)-offset > 2048 {
			size := rand.Intn(4096) + 100
			if len(b) < size {
				size = len(b)
			}
			buf = packData(buf, b[offset:size+offset])
			offset += size
		}
		if len(b)-offset > 0 {
			buf = packData(buf, b[offset:])
		}
		return buf, nil
	}

	if len(b) > 0 {
		if len(t.sendBuf) == 0 {
			t.sendBuf = pool.Get(pool.RelayBufferSize)[:0]
		}
		t.sendBuf = packData(t.sendBuf, b)
	}

	if t.handshakeStatus == 0 {
		t.handshakeStatus = 1

		data := bytes.NewBuffer([]byte{3, 3})

		authData := pool.Get(32)
		t.packAuthData(authData)
		data.Write(authData)
		pool.Put(authData)

		data.WriteByte(0x20)
		data.Write(t.clientID[:])
		data.Write([]byte{0x00, 0x1c, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14, 0xcc, 0x13, 0xc0, 0x0a, 0xc0, 0x14, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x9c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0x0a})
		data.Write([]byte{0x1, 0x0})

		ext := bytes.NewBuffer([]byte{0xff, 0x01, 0x00, 0x01, 0x00})

		host := t.getHost()
		sniBytes := pool.Get(9 + len(host))
		sni(host, sniBytes)
		ext.Write(sniBytes)
		pool.Put(sniBytes)

		ext.Write([]byte{0, 0x17, 0, 0})

		ticketBuf := t.packTicketBuf(host)
		ext.Write(ticketBuf)

		ext.Write([]byte{0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, 0x06, 0x01, 0x06, 0x03, 0x05, 0x01, 0x05, 0x03, 0x04, 0x01, 0x04, 0x03, 0x03, 0x01, 0x03, 0x03, 0x02, 0x01, 0x02, 0x03})
		ext.Write([]byte{0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00})
		ext.Write([]byte{0x00, 0x12, 0x00, 0x00})
		ext.Write([]byte{0x75, 0x50, 0x00, 0x00})
		ext.Write([]byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00})
		ext.Write([]byte{0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18})

		length := pool.Get(2)
		defer pool.Put(length)

		binary.BigEndian.PutUint16(length, uint16(ext.Len()))
		data.Write(length)
		data.Write(ext.Bytes())

		buf = append(buf, []byte{0x16, 3, 1}...)
		buf = tools.AppendUint16BigEndian(buf, uint16(data.Len()+4))
		buf = append(buf, []byte{1, 0}...)
		buf = tools.AppendUint16BigEndian(buf, uint16(data.Len()))
		buf = append(buf, data.Bytes()...)
		return buf, nil
	} else if t.handshakeStatus == 1 && len(b) == 0 {
		buf = append(buf, []byte{0x14, 3, 3, 0, 1, 1, 0x16, 3, 3, 0, 0x20}...)
		buf = tools.AppendRandBytes(buf, 22)
		buf = append(buf, t.hmacSHA1(buf)[:10]...)
		buf = append(buf, t.sendBuf...)
		pool.Put(t.sendBuf)
		t.handshakeStatus = 8
		return buf, nil
	}
	return []byte{}, nil
}

func (t *tls12Ticket) packTicketBuf(u string) []byte {
	if t.ticketBuf[u] == nil {
		bufLen := rand.Intn(17) + 8
		bufLen *= 16
		t.ticketBuf[u] = make([]byte, bufLen)
		rand.Read(t.ticketBuf[u])
	}
	ret := make([]byte, 4+len(t.ticketBuf[u]))
	copy(ret, []byte{0, 0x23})
	binary.BigEndian.PutUint16(ret[2:4], uint16(len(t.ticketBuf[u])))
	copy(ret[4:], t.ticketBuf[u])
	return ret
}

func (t *tls12Ticket) hmacSHA1(data []byte) []byte {
	key := pool.Get(len(t.Key) + 32)
	defer pool.Put(key)
	copy(key, t.Key)
	copy(key[len(t.Key):], t.clientID[:])

	sha1Data := tools.HmacSHA1(key, data)
	return sha1Data[:10]
}

func sni(u string, b []byte) {
	len := len(u)
	copy(b, []byte{0, 0})
	binary.BigEndian.PutUint16(b[2:4], uint16(len+5))
	binary.BigEndian.PutUint16(b[4:6], uint16(len+3))
	copy(b[6:7], []byte{0})
	binary.BigEndian.PutUint16(b[7:9], uint16(len))
	copy(b[9:], []byte(u))
}

func (t *tls12Ticket) getHost() string {
	host := t.Param
	if len(host) == 0 {
		host = t.Host
	}
	if len(host) > 0 && host[len(host)-1] >= '0' && host[len(host)-1] <= '9' {
		host = ""
	}
	hosts := strings.Split(host, ",")
	host = hosts[rand.Intn(len(hosts))]
	return host
}

func (t *tls12Ticket) packAuthData(authData []byte) {
	now := time.Now().Unix()
	binary.BigEndian.PutUint32(authData, uint32(now))
	rand.Read(authData[4:22])
	copy(authData[22:], t.hmacSHA1(authData[:22])[:10])
}

func packData(in, data []byte) []byte {
	in = append(in, []byte{0x17, 3, 3, 0, 0}...)
	binary.BigEndian.PutUint16(in[len(in)-2:], uint16(len(data)))
	in = append(in, data...)
	return in
}
