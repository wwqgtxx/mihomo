package shadowsocks

import (
	"github.com/Dreamacro/go-shadowsocks2/core"
	"net"

	adapters "github.com/brobird/clash/adapters/inbound"
	"github.com/brobird/clash/common/pool"
	"github.com/brobird/clash/component/socks5"
	C "github.com/brobird/clash/constant"
	"github.com/brobird/clash/tunnel"
)

type ShadowSocksUDPListener struct {
	net.PacketConn
	address string
	closed  bool
}

func NewShadowSocksUDPProxy(addr, cipher, password string) (*ShadowSocksUDPListener, error) {
	ciph, err := core.PickCipher(cipher, nil, password)
	if err != nil {
		return nil, err
	}

	l, err := net.ListenPacket("udp", addr)
	l = ciph.PacketConn(l)
	if err != nil {
		return nil, err
	}

	sl := &ShadowSocksUDPListener{l, addr, false}
	go func() {
		for {
			buf := pool.BufPool.Get().([]byte)
			n, remoteAddr, err := l.ReadFrom(buf)
			if err != nil {
				pool.BufPool.Put(buf[:cap(buf)])
				if sl.closed {
					break
				}
				continue
			}
			handleSocksUDP(l, buf[:n], remoteAddr)
		}
	}()

	return sl, nil
}

func (l *ShadowSocksUDPListener) Close() error {
	l.closed = true
	return l.PacketConn.Close()
}

func (l *ShadowSocksUDPListener) Address() string {
	return l.address
}

func handleSocksUDP(pc net.PacketConn, buf []byte, addr net.Addr) {
	target, payload, err := socks5.DecodeUDPPacket(buf)
	if err != nil {
		// Unresolved UDP packet, return buffer to the pool
		pool.BufPool.Put(buf[:cap(buf)])
		return
	}
	packet := &fakeConn{
		PacketConn: pc,
		rAddr:      addr,
		payload:    payload,
		bufRef:     buf,
	}
	tunnel.AddPacket(adapters.NewPacket(target, packet, C.SHADOWSOCKS))
}
