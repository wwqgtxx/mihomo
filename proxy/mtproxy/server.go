package mtproxy

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/Dreamacro/clash/component/mtproxy/common"
	"github.com/Dreamacro/clash/component/mtproxy/server_protocol"
	"github.com/Dreamacro/clash/component/mtproxy/telegram"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/tunnel"
)

const (
	SimpleSecretLength = common.SimpleSecretLength
	FakeTLSFirstByte   = server_protocol.FakeTLSFirstByte
)

type MTProxyListener struct {
	net.Listener
	address             string
	config              string
	closed              bool
	serverProtocolMaker common.ServerProtocolMaker
	telegramDialer      *telegram.TelegramDialer
	secret              []byte
	secretMode          common.SecretMode
	cloakHost           string
	cloakPort           string
}

var mtp *MTProxyListener

func NewMTProxy(config string) (*MTProxyListener, error) {
	spliced := strings.Split(config, "@")
	if len(spliced) != 2 {
		return nil, errors.New("addr format error")
	}
	addr := spliced[1]

	spliced2 := strings.Split(spliced[0], ":")
	secret, err := hex.DecodeString(spliced2[0])
	if err != nil {
		return nil, err
	}
	cloakPort := "443"
	if len(spliced2) == 2 {
		cloakPort = spliced2[1]
	}

	hl := &MTProxyListener{
		address:             addr,
		config:              config,
		closed:              false,
		serverProtocolMaker: server_protocol.MakeNormalServerProtocol,
		telegramDialer:      telegram.NewTelegramDialer(),
	}
	switch {
	case len(secret) == 1+SimpleSecretLength && bytes.HasPrefix(secret, []byte{0xdd}):
		hl.secretMode = common.SecretModeSecured
		hl.secret = bytes.TrimPrefix(secret, []byte{0xdd})
	case len(secret) > SimpleSecretLength && bytes.HasPrefix(secret, []byte{0xee}):
		hl.secretMode = common.SecretModeTLS
		secret := bytes.TrimPrefix(secret, []byte{0xee})
		hl.secret = secret[:SimpleSecretLength]
		hl.cloakHost = string(secret[SimpleSecretLength:])
		hl.cloakPort = cloakPort
		hl.serverProtocolMaker = server_protocol.MakeFakeTLSServerProtocol
	case len(secret) == SimpleSecretLength:
		hl.secretMode = common.SecretModeSimple
	default:
		return nil, errors.New("incorrect secret")
	}

	mtp = hl

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	hl.Listener = l

	go func() {
		log.Infoln("MTProxy listening at: %s", addr)

		for {
			c, err := hl.Accept()
			if err != nil {
				if hl.closed {
					break
				}
				continue
			}
			go hl.HandleConn(c)
		}
	}()

	return hl, nil
}

func (l *MTProxyListener) Close() {
	l.closed = true
	l.Listener.Close()
}

func (l *MTProxyListener) Address() string {
	return l.address
}

func (l *MTProxyListener) Config() string {
	return l.config
}

func (l *MTProxyListener) SecretMode() common.SecretMode {
	return l.secretMode
}

func (l *MTProxyListener) HandleConn(conn net.Conn) {
	serverProtocol := l.serverProtocolMaker(l.secret, l.secretMode, l.cloakHost, l.cloakPort)
	serverConn, err := serverProtocol.Handshake(conn)
	if err != nil {
		//logger.Warnw("Cannot perform client handshake", "error", err)

		return
	}
	defer serverConn.Close()

	telegramConn, err := l.telegramDialer.Dial(serverProtocol, func(addr string) (io.ReadWriteCloser, error) {
		conn1, conn2 := net.Pipe()
		host, port, _ := net.SplitHostPort(addr)
		remoteHost, remotePort, _ := net.SplitHostPort(conn.RemoteAddr().String())
		remoteIp := net.ParseIP(remoteHost)
		metadata := &C.Metadata{
			NetWork:  C.TCP,
			AddrType: C.AtypDomainName,
			Host:     host,
			DstIP:    nil,
			DstPort:  port,
			SrcIP:    remoteIp,
			SrcPort:  remotePort,
		}
		metadata.Type = C.MTPROXY
		connContext := context.NewConnContext(conn2, metadata)
		tunnel.Add(connContext)
		return conn1, nil
	})
	if err != nil {
		return
	}
	defer telegramConn.Close()

	wg := &sync.WaitGroup{}
	wg.Add(2)

	go directPipe(telegramConn, serverConn, wg)
	go directPipe(serverConn, telegramConn, wg)

	wg.Wait()
}

func directPipe(dst io.WriteCloser, src io.ReadCloser, wg *sync.WaitGroup) {
	defer wg.Done()
	_, _ = io.Copy(dst, src)
}

func HandleFakeTLS(conn net.Conn) bool {
	if mtp != nil && mtp.SecretMode() == common.SecretModeTLS {
		mtp.HandleConn(conn)
		return true
	}
	return false
}
