package telegram

import (
	"errors"
	"fmt"
	"io"
	"math/rand"

	"github.com/Dreamacro/clash/component/mtproxy/common"
	"github.com/Dreamacro/clash/log"
)

const (
	directV4DefaultIdx common.DC = 1
	directV6DefaultIdx common.DC = 1
)

var (
	directV4Addresses = map[common.DC][]string{
		0: {"149.154.175.50:443"},
		1: {"149.154.167.51:443"},
		2: {"149.154.175.100:443"},
		3: {"149.154.167.91:443"},
		4: {"149.154.171.5:443"},
	}
	directV6Addresses = map[common.DC][]string{
		0: {"[2001:b28:f23d:f001::a]:443"},
		1: {"[2001:67c:04e8:f002::a]:443"},
		2: {"[2001:b28:f23d:f003::a]:443"},
		3: {"[2001:67c:04e8:f004::a]:443"},
		4: {"[2001:b28:f23f:f005::a]:443"},
	}
)

type TelegramDialer struct {
	secret      []byte
	v4DefaultDC common.DC
	v6DefaultDC common.DC
	v4Addresses map[common.DC][]string
	v6Addresses map[common.DC][]string
}

func (b *TelegramDialer) Secret() []byte {
	return b.secret
}

func (b *TelegramDialer) Dial(serverProtocol common.ServerProtocol, dialFunc func(addr string) (io.ReadWriteCloser, error)) (io.ReadWriteCloser, error) {
	for _, addr := range b.getAddresses(serverProtocol.DC(), serverProtocol.ConnectionProtocol()) {
		conn, err := dialFunc(addr)
		if err != nil {
			log.Warnln("Cannot dial to Telegram, address: %s error: %s", addr, err)
			continue
		}
		conn, err = b.handshake(conn, serverProtocol.ConnectionType())
		if err != nil {
			log.Warnln("Cannot handshake to Telegram, address: %s error: %s", addr, err)
			continue
		}
		return conn, nil
	}

	return nil, errors.New("cannot dial to the chosen DC")
}

func (b *TelegramDialer) handshake(conn io.ReadWriteCloser, ct common.ConnectionType) (io.ReadWriteCloser, error) {
	fm := common.GenerateFrame(ct)
	data := fm.Bytes()

	encryptor := common.MakeStreamCipher(fm.Key(), fm.IV())
	decryptedFrame := fm.Invert()
	decryptor := common.MakeStreamCipher(decryptedFrame.Key(), decryptedFrame.IV())

	copyFrame := make([]byte, common.FrameLen)
	copy(copyFrame[:common.FrameOffsetIV], data[:common.FrameOffsetIV])
	encryptor.XORKeyStream(data, data)
	copy(data[:common.FrameOffsetIV], copyFrame[:common.FrameOffsetIV])

	if _, err := conn.Write(data); err != nil {
		return nil, fmt.Errorf("cannot write handshake frame to telegram: %w", err)
	}

	return common.NewObfuscated2(conn, encryptor, decryptor), nil
}

func (b *TelegramDialer) getAddresses(dc common.DC, protocol common.ConnectionProtocol) []string {
	switch {
	case dc < 0:
		dc = -dc
	case dc == 0:
		dc = common.DCDefaultIdx
	}

	dc = dc - 1

	addresses := make([]string, 0, 2)
	protos := []common.ConnectionProtocol{
		common.ConnectionProtocolIPv6,
		common.ConnectionProtocolIPv4,
	}

	for _, proto := range protos {
		switch {
		case proto&protocol == 0:
		case proto&common.ConnectionProtocolIPv6 != 0:
			addresses = append(addresses, b.chooseAddress(b.v6Addresses, dc, b.v6DefaultDC))
		case proto&common.ConnectionProtocolIPv4 != 0:
			addresses = append(addresses, b.chooseAddress(b.v4Addresses, dc, b.v4DefaultDC))
		}
	}

	return addresses
}

func (b *TelegramDialer) chooseAddress(addresses map[common.DC][]string, dc, defaultDC common.DC) string {
	addrs, ok := addresses[dc]
	if !ok {
		addrs = addresses[defaultDC]
	}

	switch {
	case len(addrs) == 1:
		return addrs[0]
	case len(addrs) > 1:
		return addrs[rand.Intn(len(addrs))]
	}

	return ""
}

func NewTelegramDialer() *TelegramDialer {
	return &TelegramDialer{
		v4DefaultDC: directV4DefaultIdx,
		v6DefaultDC: directV6DefaultIdx,
		v4Addresses: directV4Addresses,
		v6Addresses: directV6Addresses,
	}
}
