package server_protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	"github.com/Dreamacro/clash/component/mtproxy/common"
)

type normalServerProtocol struct {
	secret             []byte
	secretMode         common.SecretMode
	connectionType     common.ConnectionType
	connectionProtocol common.ConnectionProtocol
	dc                 common.DC
}

func (c *normalServerProtocol) ConnectionType() common.ConnectionType {
	return c.connectionType
}

func (c *normalServerProtocol) ConnectionProtocol() common.ConnectionProtocol {
	return c.connectionProtocol
}

func (c *normalServerProtocol) DC() common.DC {
	return c.dc
}

func (c *normalServerProtocol) Handshake(socket net.Conn) (net.Conn, error) {
	fm, err := c.ReadFrame(socket)
	if err != nil {
		return nil, fmt.Errorf("cannot make a client handshake: %w", err)
	}

	decHasher := sha256.New()
	decHasher.Write(fm.Key())
	decHasher.Write(c.secret)
	decryptor := common.MakeStreamCipher(decHasher.Sum(nil), fm.IV())

	invertedFrame := fm.Invert()
	encHasher := sha256.New()
	encHasher.Write(invertedFrame.Key())
	encHasher.Write(c.secret)
	encryptor := common.MakeStreamCipher(encHasher.Sum(nil), invertedFrame.IV())

	decryptedFrame := common.ServerFrame{}
	decryptor.XORKeyStream(decryptedFrame.Bytes(), fm.Bytes())

	magic := decryptedFrame.Magic()

	switch {
	case bytes.Equal(magic, common.ConnectionTagAbridged):
		c.connectionType = common.ConnectionTypeAbridged
	case bytes.Equal(magic, common.ConnectionTagIntermediate):
		c.connectionType = common.ConnectionTypeIntermediate
	case bytes.Equal(magic, common.ConnectionTagSecure):
		c.connectionType = common.ConnectionTypeSecure
	default:
		return nil, errors.New("unknown connection type")
	}

	if c.secretMode == common.SecretModeSecured && c.connectionType != common.ConnectionTypeSecure {
		return nil, errors.New("the secured mode don't support a no secure connection")
	}

	c.connectionProtocol = common.ConnectionProtocolIPv4
	if forceIPv6, _ := strconv.ParseBool(os.Getenv("MTPROXY_FORCE_IPV6")); forceIPv6 {
		c.connectionProtocol = common.ConnectionProtocolIPv6
	}

	buf := bytes.NewReader(decryptedFrame.DC())
	if err := binary.Read(buf, binary.LittleEndian, &c.dc); err != nil {
		c.dc = common.DCDefaultIdx
	}

	return common.NewObfuscated2(socket, encryptor, decryptor), nil
}

func (c *normalServerProtocol) ReadFrame(socket io.Reader) (fm common.ServerFrame, err error) {
	if _, err = io.ReadFull(socket, fm.Bytes()); err != nil {
		err = fmt.Errorf("cannot extract obfuscated2 frame: %w", err)
	}

	return
}

func MakeNormalServerProtocol(secret []byte, secretMode common.SecretMode, cloakHost string, cloakPort string) common.ServerProtocol {
	return &normalServerProtocol{
		secret:     secret,
		secretMode: secretMode,
	}
}
