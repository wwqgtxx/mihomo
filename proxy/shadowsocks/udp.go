package shadowsocks

import (
	"github.com/Dreamacro/go-shadowsocks2/core"
	"net"

	adapters "github.com/wwqgtxx/clashr/adapters/inbound"
	"github.com/wwqgtxx/clashr/common/pool"
	"github.com/wwqgtxx/clashr/component/socks5"
	C "github.com/wwqgtxx/clashr/constant"
	"github.com/wwqgtxx/clashr/tunnel"
)

type ShadowSocksUDPListener struct {
	net.PacketConn
	address string
	closed  bool
	cipher  core.Cipher
}

func NewShadowSocksUDPProxy(addr, cipher, password string) (*ShadowSocksUDPListener, error) {
	l, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}

	sl := &ShadowSocksUDPListener{l, addr, false, nil}
	err = sl.SetCipher(cipher, password)
	if err != nil {
		return nil, err
	}
	go func() {
		cipher := sl.cipher
		conn := cipher.PacketConn(l)
		for {
			buf := pool.BufPool.Get().([]byte)
			if cipher != sl.cipher { //After a SetCipher() call
				cipher = sl.cipher
				conn = cipher.PacketConn(l)
			}

			n, remoteAddr, err := conn.ReadFrom(buf)
			if err != nil {
				pool.BufPool.Put(buf[:cap(buf)])
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

func (l *ShadowSocksUDPListener) SetCipher(cipher, password string) (err error) {
	l.cipher, err = core.PickCipher(cipher, nil, password)
	return
}

func (l *ShadowSocksUDPListener) Close() error {
	l.closed = true
	return l.PacketConn.Close()
}

func (l *ShadowSocksUDPListener) Address() string {
	return l.address
}

func handleSocksUDP(pc net.PacketConn, buf []byte, addr net.Addr) {
	tgtAddr := socks5.SplitAddr(buf)
	if tgtAddr == nil {
		// Unresolved UDP packet, return buffer to the pool
		pool.BufPool.Put(buf[:cap(buf)])
		return
	}
	target := socks5.ParseAddr(tgtAddr.String())
	payload := buf[len(tgtAddr):]

	packet := &fakeConn{
		PacketConn: pc,
		rAddr:      addr,
		payload:    payload,
		bufRef:     buf,
	}
	tunnel.AddPacket(adapters.NewPacket(target, packet, C.SHADOWSOCKS))
}
