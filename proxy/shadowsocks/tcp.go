package shadowsocks

import (
	"github.com/Dreamacro/go-shadowsocks2/core"
	adapters "github.com/brobird/clash/adapters/inbound"
	"github.com/brobird/clash/component/socks5"
	C "github.com/brobird/clash/constant"
	"github.com/brobird/clash/log"
	"github.com/brobird/clash/tunnel"
	"net"
)

type ShadowSocksListener struct {
	net.Listener
	address string
	closed  bool
}

func NewShadowSocksProxy(addr, cipher, password string) (*ShadowSocksListener, error) {
	ciph, err := core.PickCipher(cipher, nil, password)
	if err != nil {
		return nil, err
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	sl := &ShadowSocksListener{l, addr, false}
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
			c = ciph.StreamConn(c)
			go handleSocks(c)
		}
	}()

	return sl, nil
}

func (l *ShadowSocksListener) Close() {
	l.closed = true
	_ = l.Listener.Close()
}

func (l *ShadowSocksListener) Address() string {
	return l.address
}

func handleSocks(conn net.Conn) {
	target, err := socks5.ReadAddr(conn, make([]byte, socks5.MaxAddrLen))
	if err != nil {
		_ = conn.Close()
		return
	}
	tunnel.Add(adapters.NewSocket(target, conn, C.SHADOWSOCKS, C.TCP))
}
