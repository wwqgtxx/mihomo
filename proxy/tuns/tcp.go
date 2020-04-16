package tuns

import (
	adapters "github.com/wwqgtxx/clashr/adapters/inbound"
	"github.com/wwqgtxx/clashr/component/socks5"
	C "github.com/wwqgtxx/clashr/constant"
	"github.com/wwqgtxx/clashr/log"
	"github.com/wwqgtxx/clashr/tunnel"
	"net"
)

type TcpTunListener struct {
	closed    bool
	config    string
	listeners []net.Listener
}

func NewTcpTunProxy(config string) (*TcpTunListener, error) {
	tl := &TcpTunListener{false, config, nil}
	pl := PairList{}
	err := pl.Set(config)
	if err != nil {
		return nil, err
	}

	for _, p := range pl {
		addr := p[0]
		target := p[1]
		go func() {
			tgt := socks5.ParseAddr(target)
			if tgt == nil {
				log.Errorln("invalid target address %q", target)
				return
			}
			l, err := net.Listen("tcp", addr)
			if err != nil {
				return
			}
			tl.listeners = append(tl.listeners, l)
			log.Infoln("TCP tunnel %s <-> %s", addr, target)
			for {
				c, err := l.Accept()
				if err != nil {
					if tl.closed {
						break
					}
					continue
				}
				_ = c.(*net.TCPConn).SetKeepAlive(true)
				tunnel.Add(adapters.NewSocket(tgt, c, C.TCPTUN, C.TCP))
			}
		}()
	}

	return tl, nil
}

func (l *TcpTunListener) Close() {
	l.closed = true
	for _, lis := range l.listeners {
		_ = lis.Close()
	}
}

func (l *TcpTunListener) Config() string {
	return l.config
}
