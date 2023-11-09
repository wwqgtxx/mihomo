package sing_tun

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"

	D "github.com/miekg/dns"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
)

const DefaultDnsReadTimeout = time.Second * 10
const DefaultDnsRelayTimeout = time.Second * 5

type DnsHandlerType func(ctx context.Context, msg *D.Msg) (*D.Msg, error)

type ListenerHandler struct {
	sing.ListenerHandler
	DnsAdds []netip.AddrPort

	getDnsHandlerMutex sync.Mutex
	defaultResolver    resolver.Resolver
	defaultHostMapper  resolver.Enhancer
	dnsHandler         DnsHandlerType
}

func (h *ListenerHandler) GetDnsHandler() (dnsHandler DnsHandlerType) {
	h.getDnsHandlerMutex.Lock()
	defer h.getDnsHandlerMutex.Unlock()

	defaultResolver := resolver.DefaultResolver
	defaultHostMapper := resolver.DefaultHostMapper
	if defaultResolver != nil {
		if defaultResolver == h.defaultResolver && defaultHostMapper == h.defaultHostMapper {
			return h.dnsHandler
		}
		_dnsHandler := dns.NewHandler(defaultResolver.(*dns.Resolver), defaultHostMapper.(*dns.ResolverEnhancer))
		dnsHandler = func(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
			return dns.HandlerWithContext(ctx, _dnsHandler, msg)
		}
		h.dnsHandler = dnsHandler
		h.defaultResolver = defaultResolver
		h.defaultHostMapper = defaultHostMapper
	}
	return
}

func (h *ListenerHandler) ShouldHijackDns(targetAddr netip.AddrPort) DnsHandlerType {
	dnsHandler := h.GetDnsHandler()
	if dnsHandler == nil {
		return nil
	}
	if targetAddr.Addr().IsLoopback() && targetAddr.Port() == 53 { // cause by system stack
		return dnsHandler
	}
	for _, addrPort := range h.DnsAdds {
		if addrPort == targetAddr || (addrPort.Addr().IsUnspecified() && targetAddr.Port() == 53) {
			return dnsHandler
		}
	}
	return nil
}

func (h *ListenerHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	if dnsHandler := h.ShouldHijackDns(metadata.Destination.AddrPort()); dnsHandler != nil {
		log.Debugln("[DNS] hijack tcp:%s", metadata.Destination.String())
		buff := pool.Get(pool.UDPBufferSize)
		defer func() {
			_ = pool.Put(buff)
			_ = conn.Close()
		}()
		for {
			if conn.SetReadDeadline(time.Now().Add(DefaultDnsReadTimeout)) != nil {
				break
			}

			length := uint16(0)
			if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
				break
			}

			if int(length) > len(buff) {
				break
			}

			n, err := io.ReadFull(conn, buff[:length])
			if err != nil {
				break
			}

			err = func() error {
				ctx, cancel := context.WithTimeout(ctx, DefaultDnsRelayTimeout)
				defer cancel()
				inData := buff[:n]
				msg, err := RelayDnsPacket(ctx, dnsHandler, inData)
				if err != nil {
					return err
				}

				err = binary.Write(conn, binary.BigEndian, uint16(len(msg)))
				if err != nil {
					return err
				}

				_, err = conn.Write(msg)
				if err != nil {
					return err
				}
				return nil
			}()
			if err != nil {
				return err
			}
		}
		return nil
	}
	return h.ListenerHandler.NewConnection(ctx, conn, metadata)
}

func (h *ListenerHandler) NewPacketConnection(ctx context.Context, conn network.PacketConn, metadata M.Metadata) error {
	if dnsHandler := h.ShouldHijackDns(metadata.Destination.AddrPort()); dnsHandler != nil {
		log.Debugln("[DNS] hijack udp:%s from %s", metadata.Destination.String(), metadata.Source.String())
		defer func() { _ = conn.Close() }()
		mutex := sync.Mutex{}
		conn2 := conn // a new interface to set nil in defer
		defer func() {
			mutex.Lock() // this goroutine must exit after all conn.WritePacket() is not running
			defer mutex.Unlock()
			conn2 = nil
		}()

		var buff *buf.Buffer
		newBuffer := func() *buf.Buffer {
			// safe size which is 1232 from https://dnsflagday.net/2020/.
			// so 2048 is enough
			buff = buf.NewSize(2 * 1024)
			return buff
		}
		readWaiter, isReadWaiter := bufio.CreatePacketReadWaiter(conn)
		if isReadWaiter {
			readWaiter.InitializeReadWaiter(newBuffer)
		}
		for {
			var (
				dest M.Socksaddr
				err  error
			)
			_ = conn.SetReadDeadline(time.Now().Add(DefaultDnsReadTimeout))
			buff = nil // clear last loop status, avoid repeat release
			if isReadWaiter {
				dest, err = readWaiter.WaitReadPacket()
			} else {
				dest, err = conn.ReadPacket(newBuffer())
			}
			if err != nil {
				if buff != nil {
					buff.Release()
				}
				if sing.ShouldIgnorePacketError(err) {
					break
				}
				return err
			}
			go func(buff *buf.Buffer) {
				ctx, cancel := context.WithTimeout(ctx, DefaultDnsRelayTimeout)
				defer cancel()
				inData := buff.Bytes()
				msg, err := RelayDnsPacket(ctx, dnsHandler, inData)
				if err != nil {
					buff.Release()
					return
				}
				buff.Reset()
				_, err = buff.Write(msg)
				if err != nil {
					buff.Release()
					return
				}
				mutex.Lock()
				defer mutex.Unlock()
				conn := conn2
				if conn == nil {
					return
				}
				err = conn.WritePacket(buff, dest) // WritePacket will release buff
				if err != nil {
					return
				}
			}(buff) // catch buff at goroutine create, avoid next loop change buff
		}
		return nil
	}
	return h.ListenerHandler.NewPacketConnection(ctx, conn, metadata)
}

func RelayDnsPacket(ctx context.Context, dnsHandle DnsHandlerType, payload []byte) ([]byte, error) {
	msg := &D.Msg{}
	if err := msg.Unpack(payload); err != nil {
		return nil, err
	}

	r, err := dnsHandle(ctx, msg)
	if err != nil {
		m := new(D.Msg)
		m.SetRcode(msg, D.RcodeServerFailure)
		return m.Pack()
	}

	r.SetRcode(msg, r.Rcode)
	r.Compress = true
	return r.Pack()
}
