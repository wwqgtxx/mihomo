package tuic

import (
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/Dreamacro/clash/adapter/inbound"
	CN "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/common/sockopt"
	C "github.com/Dreamacro/clash/constant"
	LC "github.com/Dreamacro/clash/listener/config"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/transport/socks5"
	"github.com/Dreamacro/clash/transport/tuic"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/quic-go"
	"golang.org/x/exp/slices"
)

const ServerMaxIncomingStreams = (1 << 32) - 1

type Listener struct {
	closed       bool
	config       LC.TuicServer
	udpListeners []net.PacketConn
	servers      []tuic.Server
}

func New(config LC.TuicServer, tcpIn chan<- C.ConnContext, udpIn chan<- C.PacketAdapter, additions ...inbound.Addition) (*Listener, error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-TUIC"),
			inbound.WithSpecialRules(""),
		}
	}
	cert, err := CN.ParseCert(config.Certificate, config.PrivateKey)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}
	if len(config.ALPN) > 0 {
		tlsConfig.NextProtos = config.ALPN
	} else {
		tlsConfig.NextProtos = []string{"h3"}
	}
	quicConfig := &quic.Config{
		MaxIdleTimeout:        time.Duration(config.MaxIdleTime) * time.Millisecond,
		MaxIncomingStreams:    ServerMaxIncomingStreams,
		MaxIncomingUniStreams: ServerMaxIncomingStreams,
		EnableDatagrams:       true,
		Allow0RTT:             true,
	}
	quicConfig.InitialStreamReceiveWindow = tuic.DefaultStreamReceiveWindow / 10
	quicConfig.MaxStreamReceiveWindow = tuic.DefaultStreamReceiveWindow
	quicConfig.InitialConnectionReceiveWindow = tuic.DefaultConnectionReceiveWindow / 10
	quicConfig.MaxConnectionReceiveWindow = tuic.DefaultConnectionReceiveWindow

	packetOverHead := tuic.PacketOverHeadV4
	if len(config.Token) == 0 {
		packetOverHead = tuic.PacketOverHeadV5
	}

	if config.MaxUdpRelayPacketSize == 0 {
		config.MaxUdpRelayPacketSize = 1500
	}
	maxDatagramFrameSize := config.MaxUdpRelayPacketSize + packetOverHead
	if maxDatagramFrameSize > 1400 {
		maxDatagramFrameSize = 1400
	}
	config.MaxUdpRelayPacketSize = maxDatagramFrameSize - packetOverHead
	quicConfig.MaxDatagramFrameSize = int64(maxDatagramFrameSize)

	handleTcpFn := func(conn net.Conn, addr socks5.Addr, _additions ...inbound.Addition) error {
		newAdditions := additions
		if len(_additions) > 0 {
			newAdditions = slices.Clone(additions)
			newAdditions = append(newAdditions, _additions...)
		}
		tcpIn <- inbound.NewSocket(addr, conn, C.TUIC, newAdditions...)
		return nil
	}
	handleUdpFn := func(addr socks5.Addr, packet C.UDPPacket, _additions ...inbound.Addition) error {
		newAdditions := additions
		if len(_additions) > 0 {
			newAdditions = slices.Clone(additions)
			newAdditions = append(newAdditions, _additions...)
		}
		select {
		case udpIn <- inbound.NewPacket(addr, packet, C.TUIC, newAdditions...):
		default:
		}
		return nil
	}

	var optionV4 *tuic.ServerOptionV4
	var optionV5 *tuic.ServerOptionV5
	if len(config.Token) > 0 {
		tokens := make([][32]byte, len(config.Token))
		for i, token := range config.Token {
			tokens[i] = tuic.GenTKN(token)
		}

		optionV4 = &tuic.ServerOptionV4{
			HandleTcpFn:           handleTcpFn,
			HandleUdpFn:           handleUdpFn,
			TlsConfig:             tlsConfig,
			QuicConfig:            quicConfig,
			Tokens:                tokens,
			CongestionController:  config.CongestionController,
			AuthenticationTimeout: time.Duration(config.AuthenticationTimeout) * time.Millisecond,
			MaxUdpRelayPacketSize: config.MaxUdpRelayPacketSize,
		}
	} else {
		users := make(map[[16]byte]string)
		for _uuid, password := range config.Users {
			users[uuid.FromStringOrNil(_uuid)] = password
		}

		optionV5 = &tuic.ServerOptionV5{
			HandleTcpFn:           handleTcpFn,
			HandleUdpFn:           handleUdpFn,
			TlsConfig:             tlsConfig,
			QuicConfig:            quicConfig,
			Users:                 users,
			CongestionController:  config.CongestionController,
			AuthenticationTimeout: time.Duration(config.AuthenticationTimeout) * time.Millisecond,
			MaxUdpRelayPacketSize: config.MaxUdpRelayPacketSize,
		}
	}

	sl := &Listener{false, config, nil, nil}

	for _, addr := range strings.Split(config.Listen, ",") {
		addr := addr

		ul, err := net.ListenPacket("udp", addr)
		if err != nil {
			return nil, err
		}

		err = sockopt.UDPReuseaddr(ul.(*net.UDPConn))
		if err != nil {
			log.Warnln("Failed to Reuse UDP Address: %s", err)
		}

		sl.udpListeners = append(sl.udpListeners, ul)

		var server tuic.Server
		if optionV4 != nil {
			server, err = tuic.NewServerV4(optionV4, ul)
		} else {
			server, err = tuic.NewServerV5(optionV5, ul)
		}
		if err != nil {
			return nil, err
		}

		sl.servers = append(sl.servers, server)

		go func() {
			err := server.Serve()
			if err != nil {
				if sl.closed {
					return
				}
			}
		}()
	}

	return sl, nil
}

func (l *Listener) Close() error {
	l.closed = true
	var retErr error
	for _, lis := range l.servers {
		err := lis.Close()
		if err != nil {
			retErr = err
		}
	}
	for _, lis := range l.udpListeners {
		err := lis.Close()
		if err != nil {
			retErr = err
		}
	}
	return retErr
}

func (l *Listener) Config() LC.TuicServer {
	return l.config
}

func (l *Listener) AddrList() (addrList []net.Addr) {
	for _, lis := range l.udpListeners {
		addrList = append(addrList, lis.LocalAddr())
	}
	return
}
