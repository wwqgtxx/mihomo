package shadowsocks

import (
	"github.com/Dreamacro/go-shadowsocks2/core"
	adapters "github.com/wwqgtxx/clashr/adapters/inbound"
	"github.com/wwqgtxx/clashr/component/socks5"
	C "github.com/wwqgtxx/clashr/constant"
	"github.com/wwqgtxx/clashr/log"
	"github.com/wwqgtxx/clashr/tunnel"
	"net"
)

type ShadowSocksListener struct {
	net.Listener
	config string
	closed bool
}

func NewShadowSocksProxy(config string) (*ShadowSocksListener, error) {
	addr, cipher, password, err := parseSSURL(config)
	if err != nil {
		return nil, err
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	sl := &ShadowSocksListener{l, config, false}
	pickCipher, err := core.PickCipher(cipher, nil, password)
	if err != nil {
		return nil, err
	}
	go func() {
		log.Infoln("ShadowSocks proxy listening at: %s", addr)
		for {
			c, err := l.Accept()
			if err != nil {
				if sl.closed {
					break
				}
				continue
			}
			_ = c.(*net.TCPConn).SetKeepAlive(true)
			c = pickCipher.StreamConn(c)
			go handleSocks(c)
		}
	}()

	return sl, nil
}

func (l *ShadowSocksListener) Close() {
	l.closed = true
	_ = l.Listener.Close()
}

func (l *ShadowSocksListener) Config() string {
	return l.config
}

func handleSocks(conn net.Conn) {
	target, err := socks5.ReadAddr(conn, make([]byte, socks5.MaxAddrLen))
	if err != nil {
		_ = conn.Close()
		return
	}
	tunnel.Add(adapters.NewSocket(target, conn, C.SHADOWSOCKS))
}
