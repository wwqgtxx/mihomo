package tunnel

import (
	adapters "github.com/wwqgtxx/clashr/adapters/inbound"
	"github.com/wwqgtxx/clashr/common/pool"
	"github.com/wwqgtxx/clashr/component/socks5"
	C "github.com/wwqgtxx/clashr/constant"
	"github.com/wwqgtxx/clashr/log"
	"github.com/wwqgtxx/clashr/tunnel"
	"net"
)

type UdpTunListener struct {
	closed    bool
	config    string
	listeners []net.PacketConn
}

func NewUdpTunProxy(config string) (*UdpTunListener, error) {
	ul := &UdpTunListener{false, config, nil}
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
			l, err := net.ListenPacket("udp", addr)
			if err != nil {
				return
			}
			ul.listeners = append(ul.listeners, l)
			log.Infoln("Udp tunnel %s <-> %s", addr, target)
			for {
				buf := pool.Get(pool.RelayBufferSize)
				n, remoteAddr, err := l.ReadFrom(buf)
				if err != nil {
					pool.Put(buf)
					if ul.closed {
						break
					}
					continue
				}
				packet := &packet{
					pc:      l,
					rAddr:   remoteAddr,
					payload: buf[:n],
					bufRef:  buf,
				}
				tunnel.AddPacket(adapters.NewPacket(tgt, packet, C.UDPTUN))

			}
		}()
	}

	return ul, nil
}

func (l *UdpTunListener) Close() {
	l.closed = true
	for _, lis := range l.listeners {
		_ = lis.Close()
	}
}

func (l *UdpTunListener) Config() string {
	return l.config
}
