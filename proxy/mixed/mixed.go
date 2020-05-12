package mixed

import (
	"net"
	"time"

	"github.com/wwqgtxx/clashr/common/cache"
	"github.com/wwqgtxx/clashr/component/socks5"
	"github.com/wwqgtxx/clashr/log"

	"github.com/wwqgtxx/clashr/proxy/http"
	"github.com/wwqgtxx/clashr/proxy/socks"
)

type MixedListener struct {
	net.Listener
	address string
	closed  bool
	cache   *cache.Cache
}

func NewMixedProxy(addr string) (*MixedListener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	ml := &MixedListener{l, addr, false, cache.New(30 * time.Second)}
	go func() {
		log.Infoln("Mixed(http+socks5) proxy listening at: %s", addr)

		for {
			c, err := ml.Accept()
			if err != nil {
				if ml.closed {
					break
				}
				continue
			}
			go handleConn(c, ml.cache)
		}
	}()

	return ml, nil
}

func (l *MixedListener) Close() {
	l.closed = true
	l.Listener.Close()
}

func (l *MixedListener) Address() string {
	return l.address
}

func handleConn(conn net.Conn, cache *cache.Cache) {
	bufConn := NewBufferedConn(conn)
	head, err := bufConn.Peek(1)
	if err != nil {
		return
	}

	if head[0] == socks5.Version {
		socks.HandleSocks(bufConn)
		return
	}

	http.HandleConn(bufConn, cache)
}
