package mixec

import (
	"net"
	"strings"

	"github.com/Dreamacro/clash/adapter/inbound"
	N "github.com/Dreamacro/clash/common/net"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/mtproxy"
	"github.com/Dreamacro/clash/listener/socks"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/transport/socks4"
	"github.com/Dreamacro/clash/transport/socks5"
)

type Listener struct {
	closed       bool
	config       string
	listeners    []net.Listener
	udpListeners []*socks.UDPListener
}

func New(config string, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) (*Listener, error) {
	ml := &Listener{false, config, nil, nil}
	cl := GetChanListener(tcpIn)

	for _, addr := range strings.Split(config, ",") {
		addr := addr

		//UDP
		sul, err := socks.NewUDP(addr, udpIn)
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
			log.Infoln("MixEC(RESTful Api+Socks+MTProxy+VmessWS) proxy listening at: %s", l.Addr().String())
			for {
				c, err := l.Accept()
				if err != nil {
					if ml.closed {
						break
					}
					continue
				}
				_ = c.(*net.TCPConn).SetKeepAlive(true)
				go handleECConn(c, cl, tcpIn)
			}
		}()
	}

	return ml, nil
}

func (l *Listener) Close() {
	l.closed = true
	for _, lis := range l.listeners {
		_ = lis.Close()
	}
	for _, lis := range l.udpListeners {
		_ = lis.Close()
	}
}

func (l *Listener) Config() string {
	return l.config
}

func handleECConn(conn net.Conn, cl ChanListener, in chan<- C.ConnContext) {
	bufConn := N.NewBufferedConn(conn)
	head, err := bufConn.Peek(1)
	if err != nil {
		return
	}

	switch head[0] {
	case socks4.Version: // 0x04
		socks.HandleSocks4(bufConn, in)
		return
	case socks5.Version: // 0x05
		socks.HandleSocks5(bufConn, in)
		return
	case mtproxy.FakeTLSFirstByte: // 0x16
		if mtproxy.HandleFakeTLS(bufConn, in) {
			return
		}
	}

	cl.PutConn(bufConn)
}
