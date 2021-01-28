package protocol

import (
	"bytes"
	"encoding/binary"
	"math"
	"math/rand"
	"net"
	"strconv"
	"strings"

	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/component/ssr/tools"
	"github.com/Dreamacro/clash/log"
)

type hmacMethod func(key, data []byte) []byte
type hashDigestMethod func([]byte) []byte

func init() {
	register("auth_aes128_sha1", newAuthAES128SHA1, 9)
}

type authAES128Function struct {
	salt       string
	hmac       hmacMethod
	hashDigest hashDigestMethod
}

type authAES128 struct {
	*Base
	*authData
	*authAES128Function
	*userData
	iv            []byte
	hasSentHeader bool
	rawTrans      bool
	packID        uint32
	recvID        uint32
	buf           []byte
	offset        int
}

func newAuthAES128SHA1(b *Base) Protocol {
	a := &authAES128{
		Base:               b,
		authData:           &authData{},
		authAES128Function: &authAES128Function{salt: "auth_aes128_sha1", hmac: tools.HmacSHA1, hashDigest: tools.SHA1Sum},
		userData:           &userData{},
	}
	a.initUserData()
	return a
}

func (a *authAES128) initUserData() {
	params := strings.Split(a.Param, ":")
	if len(params) > 1 {
		if userID, err := strconv.ParseUint(params[0], 10, 32); err == nil {
			binary.LittleEndian.PutUint32(a.userID[:], uint32(userID))
			a.userKey = a.hashDigest([]byte(params[1]))
		} else {
			log.Errorln("Wrong protocol-param for %s, only digits are expected before ':'", a.salt)
		}
	}
	if len(a.userKey) == 0 {
		a.userKey = a.Key
		rand.Read(a.userID[:])
	}
}

func (a *authAES128) StreamConn(c net.Conn, iv []byte) net.Conn {
	p := &authAES128{
		Base:               a.Base,
		authData:           a.authData,
		authAES128Function: a.authAES128Function,
		userData:           a.userData,
		packID:             1,
		recvID:             1,
	}
	p.iv = iv
	return &Conn{Conn: c, Protocol: p}
}

func (a *authAES128) PacketConn(c net.PacketConn) net.PacketConn {
	p := &authAES128{
		Base:               a.Base,
		authAES128Function: a.authAES128Function,
		userData:           a.userData,
	}
	return &PacketConn{PacketConn: c, Protocol: p}
}

func (a *authAES128) Decode(b []byte) ([]byte, error) {
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
		macKey := pool.Get(len(a.userKey) + 4)
		defer pool.Put(macKey)
		copy(macKey, a.userKey)
		binary.LittleEndian.PutUint32(macKey[len(a.userKey):], a.recvID)
		if !bytes.Equal(a.hmac(macKey, a.buf[a.offset:2+a.offset])[:2], a.buf[2+a.offset:4+a.offset]) {
			return nil, errAuthAES128MACError
		}

		length := int(binary.LittleEndian.Uint16(a.buf[a.offset : 2+a.offset]))
		if length >= 8192 || length < 7 {
			a.rawTrans = true
			pool.Put(a.buf)
			return nil, errAuthAES128LengthError
		}
		if length > len(a.buf)-a.offset {
			break
		}

		if !bytes.Equal(a.hmac(macKey, a.buf[a.offset:length-4+a.offset])[:4], a.buf[length-4+a.offset:length+a.offset]) {
			a.rawTrans = true
			pool.Put(a.buf)
			return nil, errAuthAES128ChksumError
		}

		a.recvID++

		pos := int(a.buf[4+a.offset])
		if pos < 255 {
			pos += 4
		} else {
			pos = int(binary.LittleEndian.Uint16(a.buf[5+a.offset:7+a.offset])) + 4
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

func (a *authAES128) Encode(buf, b []byte) ([]byte, error) {
	fullDataLength := len(b)
	if !a.hasSentHeader {
		dataLength := getDataLength(b)
		buf = a.packAuthData(buf, b[:dataLength])
		b = b[dataLength:]
		a.hasSentHeader = true
	}
	for len(b) > 8100 {
		buf = a.packData(buf, b[:8100], fullDataLength)
		b = b[8100:]
	}
	if len(b) > 0 {
		buf = a.packData(buf, b, fullDataLength)
	}
	return buf, nil
}

func (a *authAES128) DecodePacket(b []byte) ([]byte, error) {
	if !bytes.Equal(a.hmac(a.Key, b[:len(b)-4])[:4], b[len(b)-4:]) {
		return nil, errAuthAES128ChksumError
	}
	return b[:len(b)-4], nil
}

func (a *authAES128) EncodePacket(buf, b []byte) ([]byte, error) {
	buf = append(buf, b...)
	buf = append(buf, a.userID[:]...)
	buf = append(buf, a.hmac(a.userKey, buf)[:4]...)
	return buf, nil
}

func (a *authAES128) packData(poolBuf, data []byte, fullDataLength int) []byte {
	dataLength := len(data)
	randDataLength := a.getRandDataLengthForPackData(dataLength, fullDataLength)
	/*
		2:	uint16 LittleEndian packedDataLength
		2:	hmac of packedDataLength
		3:	maxRandDataLengthPrefix (min:1)
		4:	hmac of packedData except the last 4 bytes
	*/
	packedDataLength := 2 + 2 + 3 + randDataLength + dataLength + 4
	if randDataLength < 128 {
		packedDataLength -= 2
	}

	macKey := pool.Get(len(a.userKey) + 4)
	defer pool.Put(macKey)
	copy(macKey, a.userKey)
	binary.LittleEndian.PutUint32(macKey[len(a.userKey):], a.packID)
	a.packID++

	poolBuf = tools.AppendUint16LittleEndian(poolBuf, uint16(packedDataLength))
	poolBuf = append(poolBuf, a.hmac(macKey, poolBuf[len(poolBuf)-2:])[:2]...)
	poolBuf = a.packRandData(poolBuf, randDataLength)
	poolBuf = append(poolBuf, data...)
	poolBuf = append(poolBuf, a.hmac(macKey, poolBuf[len(poolBuf)-packedDataLength+4:])[:4]...)
	return poolBuf
}

func trapezoidRandom(max int, d float64) int {
	base := rand.Float64()
	if d-0 > 1e-6 {
		a := 1 - d
		base = (math.Sqrt(a*a+4*d*base) - a) / (2 * d)
	}
	return int(base * float64(max))
}

func (a *authAES128) getRandDataLengthForPackData(dataLength, fullDataLength int) int {
	if fullDataLength >= 32*1024-a.Overhead {
		return 0
	}
	// 1460: tcp_mss
	revLength := 1460 - dataLength - 9
	if revLength == 0 {
		return 0
	}
	if revLength < 0 {
		if revLength > -1460 {
			return trapezoidRandom(revLength+1460, -0.3)
		}
		return rand.Intn(32)
	}
	if dataLength > 900 {
		return rand.Intn(revLength)
	}
	return trapezoidRandom(revLength, -0.3)
}

func (a *authAES128) packAuthData(poolBuf, data []byte) []byte {
	if len(data) == 0 {
		return poolBuf
	}
	dataLength := len(data)
	randDataLength := a.getRandDataLengthForPackAuthData(dataLength)
	/*
		7:	checkHead(1) and hmac of checkHead(6)
		4:	userID
		16:	encrypted data of authdata(12), uint16 BigEndian packedDataLength(2) and uint16 BigEndian randDataLength(2)
		4:	hmac of userID and encrypted data
		4:	hmac of packedAuthData except the last 4 bytes
	*/
	packedAuthDataLength := 7 + 4 + 16 + 4 + randDataLength + dataLength + 4

	macKey := pool.Get(len(a.iv) + len(a.Key))
	defer pool.Put(macKey)
	copy(macKey, a.iv)
	copy(macKey[len(a.iv):], a.Key)

	poolBuf = append(poolBuf, byte(rand.Intn(256)))
	poolBuf = append(poolBuf, a.hmac(macKey, poolBuf)[:6]...)
	poolBuf = append(poolBuf, a.userID[:]...)
	poolBuf, err := a.authData.putEncryptedData(poolBuf, a.userKey, [2]int{packedAuthDataLength, randDataLength}, a.salt)
	if err != nil {
		return nil
	}
	poolBuf = append(poolBuf, a.hmac(macKey, poolBuf[7:])[:4]...)
	poolBuf = tools.AppendRandBytes(poolBuf, randDataLength)
	poolBuf = append(poolBuf, data...)
	poolBuf = append(poolBuf, a.hmac(a.userKey, poolBuf)[:4]...)
	return poolBuf
}

func (a *authAES128) getRandDataLengthForPackAuthData(size int) int {
	if size > 400 {
		return rand.Intn(512)
	}
	return rand.Intn(1024)
}

func (a *authAES128) packRandData(poolBuf []byte, size int) []byte {
	if size < 128 {
		poolBuf = append(poolBuf, byte(size+1))
		poolBuf = tools.AppendRandBytes(poolBuf, size)
		return poolBuf
	}
	poolBuf = append(poolBuf, 255)
	randData := pool.Get(size + 2)
	defer pool.Put(randData)
	binary.LittleEndian.PutUint16(randData, uint16(size+3))
	rand.Read(randData[2:])
	poolBuf = append(poolBuf, randData...)
	return poolBuf
}
