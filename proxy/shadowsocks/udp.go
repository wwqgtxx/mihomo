package shadowsocks

import (
	"net"

	adapters "github.com/Dreamacro/clash/adapters/inbound"
	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/common/sockopt"
	"github.com/Dreamacro/clash/component/socks5"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/tunnel"
	"github.com/Dreamacro/go-shadowsocks2/core"
)

type ShadowSocksUDPListener struct {
	net.PacketConn
	closed bool
}

func NewShadowSocksUDPProxy(addr string, pickCipher core.Cipher) (*ShadowSocksUDPListener, error) {
	l, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}

	err = sockopt.UDPReuseaddr(l.(*net.UDPConn))
	if err != nil {
		log.Warnln("Failed to Reuse UDP Address: %s", err)
	}

	sl := &ShadowSocksUDPListener{l, false}
	conn := pickCipher.PacketConn(l)
	go func() {
		for {
			buf := pool.Get(pool.RelayBufferSize)
			n, remoteAddr, err := conn.ReadFrom(buf)
			if err != nil {
				pool.Put(buf)
				if sl.closed {
					break
				}
				continue
			}
			handleSocksUDP(conn, buf[:n], remoteAddr)
		}
	}()

	return sl, nil
}

func (l *ShadowSocksUDPListener) Close() error {
	l.closed = true
	return l.PacketConn.Close()
}

func handleSocksUDP(pc net.PacketConn, buf []byte, addr net.Addr) {
	tgtAddr := socks5.SplitAddr(buf)
	if tgtAddr == nil {
		// Unresolved UDP packet, return buffer to the pool
		pool.Put(buf)
		return
	}
	target := socks5.ParseAddr(tgtAddr.String())
	payload := buf[len(tgtAddr):]

	packet := &packet{
		pc:      pc,
		rAddr:   addr,
		payload: payload,
		bufRef:  buf,
	}
	tunnel.AddPacket(adapters.NewPacket(target, packet, C.SHADOWSOCKS))
}
