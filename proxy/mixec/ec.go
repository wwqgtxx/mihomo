package mixec

import (
	"errors"
	"go.uber.org/atomic"
	"net"
	"net/http"
	"sync"

	C "github.com/Dreamacro/clash/constant"
)

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

var once sync.Once
var _chanListener *chanListener

func getChanListener() *chanListener {
	once.Do(func() {
		_chanListener = &chanListener{
			make(chan net.Conn),
			&net.TCPAddr{IP: net.IP{0, 0, 0, 0}, Port: 0},
			atomic.NewBool(false),
		}
		go http.Serve(_chanListener, C.GetECHandler())
	})
	return _chanListener
}
