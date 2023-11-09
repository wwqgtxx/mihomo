package tools

import (
	"bytes"
	"encoding/hex"
	"errors"

	"github.com/metacubex/mihomo/component/mtproxy/common"
	"github.com/metacubex/mihomo/component/mtproxy/server_protocol"
	"github.com/metacubex/mihomo/component/mtproxy/telegram"
)

type ServerInfo struct {
	TelegramDialer      *telegram.TelegramDialer
	ServerProtocolMaker common.ServerProtocolMaker
	Secret              []byte
	SecretMode          common.SecretMode
	CloakHost           string
	CloakPort           string
}

func ParseHexedSecret(hexed string) (*ServerInfo, error) {
	secret, err := hex.DecodeString(hexed)
	if err != nil {
		return nil, err
	}

	hl := &ServerInfo{
		TelegramDialer:      telegram.NewTelegramDialer(),
		ServerProtocolMaker: server_protocol.MakeNormalServerProtocol,
		CloakPort:           "443",
	}
	switch {
	case len(secret) == 1+common.SimpleSecretLength && bytes.HasPrefix(secret, []byte{0xdd}):
		hl.SecretMode = common.SecretModeSecured
		hl.Secret = bytes.TrimPrefix(secret, []byte{0xdd})
	case len(secret) > common.SimpleSecretLength && bytes.HasPrefix(secret, []byte{0xee}):
		hl.SecretMode = common.SecretModeTLS
		secret := bytes.TrimPrefix(secret, []byte{0xee})
		hl.Secret = secret[:common.SimpleSecretLength]
		hl.CloakHost = string(secret[common.SimpleSecretLength:])
		hl.ServerProtocolMaker = server_protocol.MakeFakeTLSServerProtocol
	case len(secret) == common.SimpleSecretLength:
		hl.SecretMode = common.SecretModeSimple
	default:
		return nil, errors.New("incorrect secret")
	}
	return hl, nil
}
