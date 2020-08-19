package shadowsocks

import (
	"github.com/Dreamacro/go-shadowsocks2/core"
	"net"

	adapters "github.com/Dreamacro/clash/adapters/inbound"
	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/component/socks5"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/tunnel"
)

type ShadowSocksUDPListener struct {
	net.PacketConn
	config string
	closed bool
}

func NewShadowSocksUDPProxy(config string) (*ShadowSocksUDPListener, error) {
	addr, cipher, password, err := parseSSURL(config)
	if err != nil {
		return nil, err
	}
	l, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}

	sl := &ShadowSocksUDPListener{l, config, false}
	pickCipher, err := core.PickCipher(cipher, nil, password)
	if err != nil {
		return nil, err
	}
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

func (l *ShadowSocksUDPListener) Config() string {
	return l.config
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
