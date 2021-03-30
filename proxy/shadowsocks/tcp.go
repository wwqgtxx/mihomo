package shadowsocks

import (
	"net"

	adapters "github.com/Dreamacro/clash/adapters/inbound"
	"github.com/Dreamacro/clash/component/socks5"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/tunnel"
	"github.com/Dreamacro/go-shadowsocks2/core"
)

type ShadowSocksListener struct {
	closed      bool
	config      string
	listener    net.Listener
	udpListener *ShadowSocksUDPListener
	pickCipher  core.Cipher
}

var _listener *ShadowSocksListener

func NewShadowSocksProxy(config string) (*ShadowSocksListener, error) {
	addr, cipher, password, err := parseSSURL(config)
	if err != nil {
		return nil, err
	}

	pickCipher, err := core.PickCipher(cipher, nil, password)
	if err != nil {
		return nil, err
	}

	sl := &ShadowSocksListener{false, config, nil, nil, pickCipher}

	_listener = sl

	//UDP
	ul, err := NewShadowSocksUDPProxy(addr, pickCipher)
	if err != nil {
		return nil, err
	}
	sl.udpListener = ul

	//TCP
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	sl.listener = l

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
			go sl.HandleConn(c)
		}
	}()

	return sl, nil
}

func (l *ShadowSocksListener) Close() {
	l.closed = true
	_ = l.listener.Close()
	if l.udpListener != nil {
		_ = l.udpListener.Close()
	}
}

func (l *ShadowSocksListener) Config() string {
	return l.config
}

func (l *ShadowSocksListener) HandleConn(conn net.Conn) {
	conn = l.pickCipher.StreamConn(conn)

	target, err := socks5.ReadAddr(conn, make([]byte, socks5.MaxAddrLen))
	if err != nil {
		_ = conn.Close()
		return
	}
	tunnel.Add(adapters.NewSocket(target, conn, C.SHADOWSOCKS))
}

func HandleShadowSocks(conn net.Conn) bool {
	if _listener != nil && _listener.pickCipher != nil {
		go _listener.HandleConn(conn)
		return true
	}
	return false
}
