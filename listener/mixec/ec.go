package mixec

import (
	"errors"
	"net"
	"net/http"
	"sync"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/sing_shadowsocks"
	"github.com/Dreamacro/clash/listener/sing_vmess"
	"github.com/Dreamacro/clash/transport/vmess"
	"github.com/gorilla/websocket"
	"go.uber.org/atomic"
)

type ChanListener interface {
	PutConn(conn net.Conn)
}

type chanListener struct {
	ch     chan net.Conn
	addr   net.Addr
	closed *atomic.Bool
}

func (l *chanListener) Close() error {
	if !l.closed.Swap(true) {
		close(l.ch)
	}
	return nil
}

func (l *chanListener) Accept() (net.Conn, error) {
	if conn, ok := <-l.ch; ok {
		return conn, nil
	}
	return nil, errors.New("listener closed")
}

func (l *chanListener) Addr() net.Addr {
	return l.addr
}

func (l *chanListener) PutConn(conn net.Conn) {
	if !l.closed.Load() {
		l.ch <- conn
	}
}

var once sync.Once
var _chanListener *chanListener

type ecHandler struct {
	http.Handler
	in chan<- C.ConnContext
}

func (h ecHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/socket.io" && websocket.IsWebSocketUpgrade(r) {
		conn, err := vmess.StreamUpgradedWebsocketConn(w, r)
		if err != nil {
			return
		}
		if !sing_vmess.HandleVmess(conn) {
			_ = conn.Close()
		}
		return
	}
	if r.URL.Path == "/ws" && websocket.IsWebSocketUpgrade(r) {
		conn, err := vmess.StreamUpgradedWebsocketConn(w, r)
		if err != nil {
			return
		}
		if !sing_shadowsocks.HandleShadowSocks(conn) {
			_ = conn.Close()
		}
		return
	}

	h.Handler.ServeHTTP(w, r)
}

func GetChanListener(in chan<- C.ConnContext) ChanListener {
	once.Do(func() {
		_chanListener = &chanListener{
			make(chan net.Conn),
			&net.TCPAddr{IP: net.IP{0, 0, 0, 0}, Port: 0},
			atomic.NewBool(false),
		}
		go http.Serve(_chanListener, ecHandler{C.GetECHandler(), in})
	})
	return _chanListener
}
