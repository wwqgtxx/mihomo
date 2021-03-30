package mixec

import (
	"errors"
	"net"
	"net/http"
	"sync"

	"github.com/Dreamacro/clash/component/vmess"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/proxy/shadowsocks"
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

var upgrader = websocket.Upgrader{}

var once sync.Once
var _chanListener *chanListener

type ecHandler struct {
	http.Handler
}

func (h ecHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		//defer ws.Close()
		conn := vmess.StreamUpgradedWebsocketConn(ws)
		if !shadowsocks.HandleShadowSocks(conn) {
			_ = ws.Close()
		}
		return
	}

	h.Handler.ServeHTTP(w, r)
}

func GetChanListener() ChanListener {
	once.Do(func() {
		_chanListener = &chanListener{
			make(chan net.Conn),
			&net.TCPAddr{IP: net.IP{0, 0, 0, 0}, Port: 0},
			atomic.NewBool(false),
		}
		go http.Serve(_chanListener, ecHandler{C.GetECHandler()})
	})
	return _chanListener
}
