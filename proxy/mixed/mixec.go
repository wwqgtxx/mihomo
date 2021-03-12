package mixed

import (
	"errors"
	"net"
	"net/http"

	"github.com/Dreamacro/clash/component/socks5"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/proxy/mtproxy"
	"github.com/Dreamacro/clash/proxy/socks"
)

type MixECListener struct {
	net.Listener
	address string
	closed  bool
	ch      chan net.Conn
}

func NewMixECProxy(addr string) (*MixECListener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	ml := &MixECListener{l, addr, false, make(chan net.Conn)}

	go http.Serve(ml, C.GetECHandler())
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
			go handleECConn(c, ml.ch)
		}
	}()

	return ml, nil
}

func (l *MixECListener) Close() error {
	close(l.ch)
	l.closed = true
	return l.Listener.Close()
}

func (l *MixECListener) Address() string {
	return l.address
}

func (l *MixECListener) Accept() (net.Conn, error) {
	if conn, ok := <-l.ch; ok {
		return conn, nil
	}
	return nil, errors.New("listener closed")
}

func handleECConn(conn net.Conn, ch chan net.Conn) {
	bufConn := NewBufferedConn(conn)
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
