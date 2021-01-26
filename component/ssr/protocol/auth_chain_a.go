package protocol

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rc4"
	"encoding/base64"
	"encoding/binary"
	"net"
	"strconv"
	"strings"

	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/component/ssr/tools"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/go-shadowsocks2/core"
)

func init() {
	register("auth_chain_a", newAuthChainA, 4)
}

type randDataLengthMethod func(int, []byte, *tools.XorShift128Plus) int

type authChainA struct {
	*Base
	*authData
	*userData
	salt           string
	hasSentHeader  bool
	rawTrans       bool
	buf            []byte
	offset         int
	lastClientHash []byte
	lastServerHash []byte
	encrypter      cipher.Stream
	decrypter      cipher.Stream
	randomClient   tools.XorShift128Plus
	randomServer   tools.XorShift128Plus
	randDataLength randDataLengthMethod
	packID         uint32
	recvID         uint32
}

func newAuthChainA(b *Base) Protocol {
	a := &authChainA{
		Base:     b,
		authData: &authData{},
		userData: &userData{},
		salt:     "auth_chain_a",
	}
	a.initUserData()
	return a
}

func (a *authChainA) initUserData() {
	params := strings.Split(a.Param, ":")
	if len(params) > 1 {
		if userID, err := strconv.ParseUint(params[0], 10, 32); err == nil {
			binary.LittleEndian.PutUint32(a.userID[:], uint32(userID))
			a.userKey = []byte(params[1])
		} else {
			log.Errorln("Wrong protocol-param for %s, only digits are expected before ':'", a.salt)
		}
	}
	if len(a.userKey) == 0 {
		a.userKey = a.Key
		rand.Read(a.userID[:])
	}
}

func (a *authChainA) StreamConn(c net.Conn, iv []byte) net.Conn {
	p := &authChainA{
		Base:     a.Base,
		authData: a.authData,
		userData: a.userData,
		salt:     a.salt,
		packID:   1,
		recvID:   1,
	}
	p.IV = iv
	p.randDataLength = p.getRandLength
	return &Conn{Conn: c, Protocol: p}
}

func (a *authChainA) PacketConn(c net.PacketConn) net.PacketConn {
	p := &authChainA{
		Base:     a.Base,
		salt:     a.salt,
		userData: a.userData,
	}
	return &PacketConn{PacketConn: c, Protocol: p}
}

func (a *authChainA) Decode(b []byte) ([]byte, error) {
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

		dataLength := int(binary.LittleEndian.Uint16(a.buf[a.offset:2+a.offset]) ^ binary.LittleEndian.Uint16(a.lastServerHash[14:16]))
		randDataLength := a.randDataLength(dataLength, a.lastServerHash, &a.randomServer)
		length := dataLength + randDataLength

		if length >= 4096 {
			a.rawTrans = true
			pool.Put(a.buf)
			return nil, errAuthChainLengthError
		}

		if 4+length > len(a.buf)-a.offset {
			break
		}

		serverHash := tools.HmacMD5(macKey, a.buf[a.offset:a.offset+length+2])
		if !bytes.Equal(serverHash[:2], a.buf[a.offset+length+2:a.offset+length+4]) {
			a.rawTrans = true
			pool.Put(a.buf)
			return nil, errAuthChainChksumError
		}
		a.lastServerHash = serverHash

		pos := 2 + getRandStartPos(randDataLength, &a.randomServer)
		wantedData := a.buf[a.offset+pos : a.offset+pos+dataLength]
		a.decrypter.XORKeyStream(wantedData, wantedData)
		b = append(b, wantedData...)
		if a.recvID == 1 {
			b = b[2:]
		}
		a.recvID++
		a.offset += length + 4
		if len(a.buf) == a.offset {
			pool.Put(a.buf)
			a.buf = nil
			a.offset = 0
		}
	}
	return b, nil
}

func (a *authChainA) Encode(buf, b []byte) ([]byte, error) {
	if !a.hasSentHeader {
		dataLength := getDataLength(b)
		buf = a.packAuthData(buf, b[:dataLength])
		b = b[dataLength:]
		a.hasSentHeader = true
	}
	for len(b) > 2800 {
		buf = a.packData(buf, b[:2800])
		b = b[2800:]
	}
	if len(b) > 0 {
		buf = a.packData(buf, b)
	}
	return buf, nil
}

func (a *authChainA) DecodePacket(b []byte) ([]byte, error) {
	if len(b) < 9 {
		return nil, errAuthChainLengthError
	}
	if !bytes.Equal(tools.HmacMD5(a.userKey, b[:len(b)-1])[:1], b[len(b)-1:]) {
		return nil, errAuthChainChksumError
	}
	md5Data := tools.HmacMD5(a.Key, b[len(b)-8:len(b)-1])

	randDataLength := udpGetRandLength(md5Data, &a.randomServer)

	key := core.Kdf(base64.StdEncoding.EncodeToString(a.userKey)+base64.StdEncoding.EncodeToString(md5Data), 16)
	rc4Cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	wantedData := b[:len(b)-8-randDataLength]
	rc4Cipher.XORKeyStream(wantedData, wantedData)
	return wantedData, nil
}

func (a *authChainA) EncodePacket(buf, b []byte) ([]byte, error) {
	authData := pool.Get(3)
	defer pool.Put(authData)
	rand.Read(authData)

	md5Data := tools.HmacMD5(a.Key, authData)

	randDataLength := udpGetRandLength(md5Data, &a.randomClient)

	key := core.Kdf(base64.StdEncoding.EncodeToString(a.userKey)+base64.StdEncoding.EncodeToString(md5Data), 16)
	rc4Cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	rc4Cipher.XORKeyStream(b, b)

	buf = append(buf, b...)
	buf = tools.AppendRandBytes(buf, randDataLength)
	buf = append(buf, authData...)
	buf = tools.AppendUint32LittleEndian(buf, binary.LittleEndian.Uint32(a.userID[:])^binary.LittleEndian.Uint32(md5Data[:4]))
	return append(buf, tools.HmacMD5(a.userKey, buf)[:1]...), nil
}

func (a *authChainA) packAuthData(poolBuf, data []byte) []byte {
	/*
		dataLength := len(data)
		12:	checkHead(4) and hmac of checkHead(8)
		4:	uint32 LittleEndian uid (uid = userID ^ last client hash)
		16:	encrypted data of authdata(12), uint16 LittleEndian overhead(2) and uint16 LittleEndian number zero(2)
		4:	last server hash(4)
		packedAuthDataLength := 12 + 4 + 16 + 4 + dataLength
	*/

	macKey := pool.Get(len(a.IV) + len(a.Key))
	defer pool.Put(macKey)
	copy(macKey, a.IV)
	copy(macKey[len(a.IV):], a.Key)

	// check head
	poolBuf = tools.AppendRandBytes(poolBuf, 4)
	a.lastClientHash = tools.HmacMD5(macKey, poolBuf)
	a.initRC4Cipher()
	poolBuf = append(poolBuf, a.lastClientHash[:8]...)
	// uid
	poolBuf = tools.AppendUint32LittleEndian(poolBuf, binary.LittleEndian.Uint32(a.userID[:])^binary.LittleEndian.Uint32(a.lastClientHash[8:12]))
	// encrypted data
	poolBuf, err := a.putEncryptedData(poolBuf, a.userKey, [2]int{a.Overhead, 0}, a.salt)
	if err != nil {
		return nil
	}
	// last server hash
	a.lastServerHash = tools.HmacMD5(a.userKey, poolBuf[12:])
	poolBuf = append(poolBuf, a.lastServerHash[:4]...)
	// packed data
	return a.packData(poolBuf, data)
}

func (a *authChainA) packData(poolBuf, data []byte) []byte {
	a.encrypter.XORKeyStream(data, data)

	macKey := pool.Get(len(a.userKey) + 4)
	defer pool.Put(macKey)
	copy(macKey, a.userKey)
	binary.LittleEndian.PutUint32(macKey[len(a.userKey):], a.packID)
	a.packID++

	length := uint16(len(data)) ^ binary.LittleEndian.Uint16(a.lastClientHash[14:16])

	originalLength := len(poolBuf)
	poolBuf = tools.AppendUint16LittleEndian(poolBuf, length)
	poolBuf = a.putMixedRandDataAndData(poolBuf, data)
	a.lastClientHash = tools.HmacMD5(macKey, poolBuf[originalLength:])
	return append(poolBuf, a.lastClientHash[:2]...)
}

func (a *authChainA) putMixedRandDataAndData(poolBuf, data []byte) []byte {
	randDataLength := a.randDataLength(len(data), a.lastClientHash, &a.randomClient)
	startPos := getRandStartPos(randDataLength, &a.randomClient)
	poolBuf = tools.AppendRandBytes(poolBuf, startPos)
	poolBuf = append(poolBuf, data...)
	return tools.AppendRandBytes(poolBuf, randDataLength-startPos)
}

func getRandStartPos(length int, random *tools.XorShift128Plus) int {
	if length == 0 {
		return 0
	}
	return int(random.Next()%8589934609) % length
}

func (a *authChainA) getRandLength(length int, lastHash []byte, random *tools.XorShift128Plus) int {
	if length > 1440 {
		return 0
	}
	random.InitFromBinAndLength(lastHash, length)
	if length > 1300 {
		return int(random.Next() % 31)
	}
	if length > 900 {
		return int(random.Next() % 127)
	}
	if length > 400 {
		return int(random.Next() % 521)
	}
	return int(random.Next() % 1021)
}

func (a *authChainA) initRC4Cipher() {
	key := core.Kdf(base64.StdEncoding.EncodeToString(a.userKey)+base64.StdEncoding.EncodeToString(a.lastClientHash), 16)
	a.encrypter, _ = rc4.NewCipher(key)
	a.decrypter, _ = rc4.NewCipher(key)
}

func udpGetRandLength(lastHash []byte, random *tools.XorShift128Plus) int {
	random.InitFromBin(lastHash)
	return int(random.Next() % 127)
}
