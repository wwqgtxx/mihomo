package protocol

import (
	"bytes"
	"encoding/binary"
	"hash/adler32"
	"hash/crc32"
	"math/rand"
	"net"

	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/component/ssr/tools"
)

func init() {
	register("auth_sha1_v4", newAuthSHA1V4, 7)
}

type authSHA1V4 struct {
	*Base
	*authData
	hasSentHeader bool
	rawTrans      bool
	buf           []byte
	offset        int
}

func newAuthSHA1V4(b *Base) Protocol {
	return &authSHA1V4{Base: b, authData: &authData{}}
}

func (a *authSHA1V4) StreamConn(c net.Conn, iv []byte) net.Conn {
	p := &authSHA1V4{Base: a.Base, authData: a.authData}
	p.IV = iv
	return &Conn{Conn: c, Protocol: p}
}

func (a *authSHA1V4) PacketConn(c net.PacketConn) net.PacketConn {
	return c
}

func (a *authSHA1V4) Decode(b []byte) ([]byte, error) {
	if a.rawTrans {
		return b, nil
	}
	if a.buf == nil {
		if len(b) == 0 {
			return b, nil
		}
		a.buf = pool.Get(pool.RelayBufferSize)[:0]
	}
	a.buf = append(a.buf, b...)
	b = b[:0]
	for len(a.buf)-a.offset > 4 {
		crc := pool.Get(2)
		defer pool.Put(crc)
		binary.LittleEndian.PutUint16(crc, uint16(crc32.ChecksumIEEE(a.buf[a.offset:2+a.offset])&0xffff))
		if !bytes.Equal(crc, a.buf[2+a.offset:4+a.offset]) {
			return nil, errAuthSHA1V4CRC32Error
		}

		length := int(binary.BigEndian.Uint16(a.buf[a.offset : 2+a.offset]))
		if length >= 8192 || length < 7 {
			a.rawTrans = true
			pool.Put(a.buf)
			return nil, errAuthSHA1V4LengthError
		}
		if length > len(a.buf)-a.offset {
			break
		}

		adler := pool.Get(4)
		defer pool.Put(adler)
		binary.LittleEndian.PutUint32(adler, adler32.Checksum(a.buf[a.offset:length-4+a.offset]))
		if !bytes.Equal(adler, a.buf[length-4+a.offset:length+a.offset]) {
			a.rawTrans = true
			pool.Put(a.buf)
			return nil, errAuthSHA1V4Adler32Error
		}

		pos := int(a.buf[4+a.offset])
		if pos < 255 {
			pos += 4
		} else {
			pos = int(binary.BigEndian.Uint16(a.buf[5+a.offset:7+a.offset])) + 4
		}
		b = append(b, a.buf[pos+a.offset:length-4+a.offset]...)
		a.offset += length
		if len(a.buf) == a.offset {
			pool.Put(a.buf)
			a.buf = nil
			a.offset = 0
		}
	}
	return b, nil
}

func (a *authSHA1V4) Encode(buf, b []byte) ([]byte, error) {
	offset := 0
	if !a.hasSentHeader {
		dataLength := getDataLength(b)

		buf = a.packAuthData(buf, b[offset:offset+dataLength])

		offset += dataLength
		a.hasSentHeader = true
	}
	for len(b)-offset > 8100 {
		buf = a.packData(buf, b[offset:8100+offset])
		offset += 8100
	}
	if len(b)-offset > 0 {
		buf = a.packData(buf, b[offset:])
	}

	return buf, nil
}

func (a *authSHA1V4) DecodePacket(b []byte) ([]byte, error) { return b, nil }

func (a *authSHA1V4) EncodePacket(buf, b []byte) ([]byte, error) { return b, nil }

func (a *authSHA1V4) packData(poolBuf, data []byte) []byte {
	dataLength := len(data)
	randDataLength := a.getRandDataLength(dataLength)
	/*
		2:	uint16 BigEndian packedDataLength
		2:	uint16 LittleEndian crc32Data & 0xffff
		3:	maxRandDataLengthPrefix (min:1)
		4:	adler32Data
	*/
	packedDataLength := 2 + 2 + 3 + randDataLength + dataLength + 4
	if randDataLength < 128 {
		packedDataLength -= 2
	}

	poolBuf = tools.AppendUint16BigEndian(poolBuf, uint16(packedDataLength))
	poolBuf = tools.AppendUint16LittleEndian(poolBuf, uint16(crc32.ChecksumIEEE(poolBuf[len(poolBuf)-2:])&0xffff))
	poolBuf = a.packRandData(poolBuf, randDataLength)
	poolBuf = append(poolBuf, data...)
	poolBuf = tools.AppendUint32LittleEndian(poolBuf, adler32.Checksum(poolBuf[len(poolBuf)-packedDataLength+4:]))

	return poolBuf
}

func (a *authSHA1V4) packAuthData(poolBuf, data []byte) []byte {
	dataLength := len(data)
	randDataLength := a.getRandDataLength(12 + dataLength)
	/*
		2:	uint16 BigEndian packedAuthDataLength
		4:	uint32 LittleEndian crc32Data
		3:	maxRandDataLengthPrefix (min: 1)
		12:	authDataLength
		10:	hmacSHA1DataLength
	*/
	packedAuthDataLength := 2 + 4 + 3 + randDataLength + 12 + dataLength + 10
	if randDataLength < 128 {
		packedAuthDataLength -= 2
	}

	salt := []byte("auth_sha1_v4")
	crcData := pool.Get(len(salt) + len(a.Key) + 2)
	defer pool.Put(crcData)
	binary.BigEndian.PutUint16(crcData, uint16(packedAuthDataLength))
	copy(crcData[2:], salt)
	copy(crcData[2+len(salt):], a.Key)

	key := pool.Get(len(a.IV) + len(a.Key))
	defer pool.Put(key)
	copy(key, a.IV)
	copy(key[len(a.IV):], a.Key)

	poolBuf = append(poolBuf, crcData[:6]...)
	binary.LittleEndian.PutUint32(poolBuf[len(poolBuf)-4:], crc32.ChecksumIEEE(crcData))
	poolBuf = a.packRandData(poolBuf, randDataLength)
	poolBuf = a.authData.putAuthData(poolBuf)
	poolBuf = append(poolBuf, data...)
	poolBuf = append(poolBuf, tools.HmacSHA1(key, poolBuf[len(poolBuf)-packedAuthDataLength+10:])[:10]...)
	return poolBuf
}

func (a *authSHA1V4) packRandData(poolBuf []byte, size int) []byte {
	if size < 128 {
		poolBuf = append(poolBuf, byte(size+1))
		poolBuf = tools.AppendRandBytes(poolBuf, size)
		return poolBuf
	}
	poolBuf = append(poolBuf, 255)
	randData := pool.Get(size + 2)
	defer pool.Put(randData)
	binary.BigEndian.PutUint16(randData, uint16(size+3))
	rand.Read(randData[2:])
	poolBuf = append(poolBuf, randData...)
	return poolBuf
}

func (a *authSHA1V4) getRandDataLength(size int) int {
	if size > 1200 {
		return 0
	}
	if size > 400 {
		return rand.Intn(256)
	}
	return rand.Intn(512)
}
