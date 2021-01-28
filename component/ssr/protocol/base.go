package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"math/rand"
	"time"

	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/component/ssr/tools"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/go-shadowsocks2/core"
)

type Base struct {
	Key      []byte
	Overhead int
	Param    string
}

type userData struct {
	userKey []byte
	userID  [4]byte
}

type authData struct {
	clientID     [4]byte
	connectionID uint32
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

func (a *authData) putEncryptedData(b, userKey []byte, paddings [2]int, salt string) ([]byte, error) {
	encrypt := pool.Get(16)[:0]
	defer pool.Put(encrypt)
	encrypt = a.putAuthData(encrypt)
	encrypt = tools.AppendUint16LittleEndian(encrypt, uint16(paddings[0]))
	encrypt = tools.AppendUint16LittleEndian(encrypt, uint16(paddings[1]))
	cipherKey := core.Kdf(base64.StdEncoding.EncodeToString(userKey)+salt, 16)
	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		log.Errorln("New cipher error: %s", err.Error())
		return nil, err
	}
	iv := bytes.Repeat([]byte{0}, 16)
	cbcCipher := cipher.NewCBCEncrypter(block, iv)
	cbcCipher.CryptBlocks(encrypt, encrypt)

	return append(b, encrypt...), nil
}
