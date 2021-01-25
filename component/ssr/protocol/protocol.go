package protocol

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/Dreamacro/clash/component/ssr/tools"
)

var (
	errAuthSHA1V4CRC32Error   = errors.New("auth_sha1_v4 decode data wrong crc32")
	errAuthSHA1V4LengthError  = errors.New("auth_sha1_v4 decode data wrong length")
	errAuthSHA1V4Adler32Error = errors.New("auth_sha1_v4 decode data wrong adler32")
	errAuthAES128MACError     = errors.New("auth_aes128_* decode data wrong mac")
	errAuthAES128LengthError  = errors.New("auth_aes128_* decode data wrong length")
	errAuthAES128ChksumError  = errors.New("auth_aes128_* decode data wrong checksum")
)

type authData struct {
	clientID     [4]byte
	connectionID uint32
}

type Protocol interface {
	StreamConn(net.Conn, []byte) net.Conn
	PacketConn(net.PacketConn) net.PacketConn
	Decode([]byte) ([]byte, error)
	Encode(buf, b []byte) ([]byte, error)
	DecodePacket([]byte) ([]byte, error)
	EncodePacket(buf, b []byte) ([]byte, error)
}

type protocolCreator func(b *Base) Protocol

var protocolList = make(map[string]struct {
	overhead int
	new      protocolCreator
})

func register(name string, c protocolCreator, o int) {
	protocolList[name] = struct {
		overhead int
		new      protocolCreator
	}{overhead: o, new: c}
}

func PickProtocol(name string, b *Base) (Protocol, error) {
	if choice, ok := protocolList[name]; ok {
		b.Overhead += choice.overhead
		return choice.new(b), nil
	}
	return nil, fmt.Errorf("protocol %s not supported", name)
}

func getHeadSize(b []byte, defaultValue int) int {
	if len(b) < 2 {
		return defaultValue
	}
	headType := b[0] & 7
	switch headType {
	case 1:
		return 7
	case 4:
		return 19
	case 3:
		return 4 + int(b[1])
	}
	return defaultValue
}

func getDataLength(b []byte) int {
	bLength := len(b)
	dataLength := getHeadSize(b, 30) + rand.Intn(32)
	if bLength < dataLength {
		return bLength
	}
	return dataLength
}

func (a *authData) putAuthData(b []byte) []byte {
	now := uint32(time.Now().Unix())
	if a.connectionID > 0xff000000 || a.connectionID == 0 {
		rand.Read(a.clientID[:])
		a.connectionID = rand.Uint32() & 0xffffff
	}
	a.connectionID++

	b = tools.AppendUint32LittleEndian(b, now)
	b = append(b, a.clientID[:]...)
	b = tools.AppendUint32LittleEndian(b, a.connectionID)
	return b
}
