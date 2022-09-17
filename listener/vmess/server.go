package vmess

import (
	"context"
	"net"
	"strings"
	"sync"

	"github.com/Dreamacro/clash/adapter/inbound"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/transport/socks5"

	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
)

type Listener struct {
	closed    bool
	config    string
	listeners []net.Listener
	service   *vmess.Service[string]
}

var _listener *Listener

type handler struct {
	tcpIn chan<- C.ConnContext
	udpIn chan<- *inbound.PacketAdapter
}

type waitCloseConn struct {
	net.Conn
	wg    *sync.WaitGroup
	close sync.Once
}

func (c *waitCloseConn) Close() error { // call from handleTCPConn(connCtx C.ConnContext)
	c.close.Do(func() {
		c.wg.Done()
	})
	return c.Conn.Close()
}

func (h *handler) NewConnection(ctx context.Context, conn net.Conn, metadata metadata.Metadata) error {
	target := socks5.ParseAddr(metadata.Destination.String())
	wg := &sync.WaitGroup{}
	defer wg.Wait() // this goroutine must exit after conn.Close()
	wg.Add(1)
	h.tcpIn <- inbound.NewSocket(target, &waitCloseConn{Conn: conn, wg: wg}, C.VMESS)
	return nil
}

func (h *handler) NewPacketConnection(ctx context.Context, conn network.PacketConn, metadata metadata.Metadata) error {
	defer func() { _ = conn.Close() }()
	mutex := sync.Mutex{}
	conn2 := conn // a new interface to set nil in defer
	defer func() {
		mutex.Lock() // this goroutine must exit after all conn.WritePacket() is not running
		defer mutex.Unlock()
		conn2 = nil
	}()
	for {
		buff := buf.NewPacket() // do not use stack buffer
		dest, err := conn.ReadPacket(buff)
		if err != nil {
			buff.Release()
			return err
		}
		target := socks5.ParseAddr(dest.String())
		packet := &packet{
			conn:  &conn2,
			mutex: &mutex,
			rAddr: metadata.Source.UDPAddr(),
			lAddr: conn.LocalAddr(),
			buff:  buff,
		}
		select {
		case h.udpIn <- inbound.NewPacket(target, packet, C.VMESS):
		default:
		}
	}
}

func New(config string, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) (*Listener, error) {
	addr, username, password, err := parseVmessURL(config)
	if err != nil {
		return nil, err
	}

	h := &handler{
		tcpIn: tcpIn,
		udpIn: udpIn,
	}

	service := vmess.NewService[string](h)
	err = service.UpdateUsers([]string{username}, []string{password}, []int{1})
	if err != nil {
		return nil, err
	}

	err = service.Start()
	if err != nil {
		return nil, err
	}

	sl := &Listener{false, config, nil, service}
	_listener = sl

	for _, addr := range strings.Split(addr, ",") {
		addr := addr

		//TCP
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		sl.listeners = append(sl.listeners, l)

		go func() {
			log.Infoln("Vmess proxy listening at: %s", l.Addr().String())
			for {
				c, err := l.Accept()
				if err != nil {
					if sl.closed {
						break
					}
					continue
				}
				_ = c.(*net.TCPConn).SetKeepAlive(true)

				go sl.HandleConn(c)
			}
		}()
	}

	return sl, nil
}

func (l *Listener) Close() {
	l.closed = true
	for _, lis := range l.listeners {
		_ = lis.Close()
	}
	_ = l.service.Close()
}

func (l *Listener) Config() string {
	return l.config
}

func (l *Listener) HandleConn(conn net.Conn) {
	err := l.service.NewConnection(context.TODO(), conn, metadata.Metadata{
		Protocol: "vmess",
		Source:   metadata.ParseSocksaddr(conn.RemoteAddr().String()),
	})
	if err != nil {
		_ = conn.Close()
		return
	}
}

func HandleVmess(conn net.Conn) bool {
	if _listener != nil && _listener.service != nil {
		go _listener.HandleConn(conn)
		return true
	}
	return false
}
