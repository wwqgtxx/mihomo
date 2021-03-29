package mixec

import (
	"net"
	"strings"

	"github.com/Dreamacro/clash/component/socks5"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/proxy/mixed"
	"github.com/Dreamacro/clash/proxy/mtproxy"
	"github.com/Dreamacro/clash/proxy/socks"
)

type MixECListener struct {
	closed       bool
	config       string
	listeners    []net.Listener
	udpListeners []*socks.SockUDPListener
}

func NewMixECProxy(config string) (*MixECListener, error) {
	ml := &MixECListener{false, config, nil, nil}
	cl := getChanListener()

	for _, addr := range strings.Split(config, ",") {
		addr := addr

		//UDP
		sul, err := socks.NewSocksUDPProxy(addr)
		if err != nil {
			return nil, err
		}
		ml.udpListeners = append(ml.udpListeners, sul)

		//TCP
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		ml.listeners = append(ml.listeners, l)

		go func() {
			log.Infoln("MixEC(RESTful Api+socks5+MTProxy) proxy listening at: %s", addr)
			for {
				c, err := l.Accept()
				if err != nil {
					if ml.closed {
						break
					}
					continue
				}
				_ = c.(*net.TCPConn).SetKeepAlive(true)
				go handleECConn(c, cl.ch)
			}
		}()
	}

	return ml, nil
}

func (l *MixECListener) Close() {
	l.closed = true
	for _, lis := range l.listeners {
		_ = lis.Close()
	}
	for _, lis := range l.udpListeners {
		_ = lis.Close()
	}
}

func (l *MixECListener) Config() string {
	return l.config
}

func handleECConn(conn net.Conn, ch chan net.Conn) {
	bufConn := mixed.NewBufferedConn(conn)
	head, err := bufConn.Peek(1)
	if err != nil {
		return
	}

	switch head[0] {
	case socks5.Version: // 0x5
		socks.HandleSocks(bufConn)
		return
	case mtproxy.FakeTLSFirstByte: // 0x16
		if mtproxy.HandleFakeTLS(bufConn) {
			return
		}
	}

	ch <- bufConn
}
