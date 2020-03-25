package tun

import (
	"fmt"
	"net"
	"strings"
	"syscall"

	adapters "github.com/Dreamacro/clash/adapters/inbound"
	"github.com/Dreamacro/clash/component/socks5"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/tunnel"

	"encoding/binary"

	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/adapters/gonet"
	"github.com/google/netstack/tcpip/link/fdbased"
	"github.com/google/netstack/tcpip/link/rawfile"
	netstacktun "github.com/google/netstack/tcpip/link/tun"
	"github.com/google/netstack/tcpip/network/ipv4"
	"github.com/google/netstack/tcpip/network/ipv6"
	"github.com/google/netstack/tcpip/stack"
	"github.com/google/netstack/tcpip/transport/tcp"
	"github.com/google/netstack/waiter"
)

var (
	tun     = tunnel.Instance()
	ipstack *stack.Stack
)

// TunAdapter is the wraper of tun
type TunAdapter struct {
	tunfd   int
	ipstack *stack.Stack
	ifName  string
}

// NewTunProxy create TunProxy under Linux OS.
func NewTunProxy(linuxIfName string) (*TunAdapter, error) {

	var err error
	tunfd, err := netstacktun.Open(linuxIfName)

	if err != nil {
		return nil, fmt.Errorf("Can't open tun: %v", err)

	}

	ipstack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocol{ipv4.NewProtocol(), ipv6.NewProtocol()},
		TransportProtocols: []stack.TransportProtocol{tcp.NewProtocol()},
	})

	mtu, err := rawfile.GetMTU(linuxIfName)
	if err != nil {
		return nil, fmt.Errorf("Can't get MTU from tun: %v", err)
	}

	linkEP, err := fdbased.New(&fdbased.Options{
		FDs:            []int{tunfd},
		MTU:            mtu,
		EthernetHeader: false,
	})

	if err := ipstack.CreateNIC(1, linkEP); err != nil {
		return nil, fmt.Errorf("Fail to create NIC in ipstack: %v", err)

	}

	// IPv4 0.0.0.0/0
	subnet, _ := tcpip.NewSubnet(tcpip.Address(strings.Repeat("\x00", 4)), tcpip.AddressMask(strings.Repeat("\x00", 4)))
	ipstack.AddAddressRange(1, ipv4.ProtocolNumber, subnet)

	// IPv6 [::]/0
	subnet, _ = tcpip.NewSubnet(tcpip.Address(strings.Repeat("\x00", 16)), tcpip.AddressMask(strings.Repeat("\x00", 16)))
	ipstack.AddAddressRange(1, ipv4.ProtocolNumber, subnet)

	// TCP handler
	tcpForwarder := tcp.NewForwarder(ipstack, 0, 16, func(r *tcp.ForwarderRequest) {
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			log.Warnln("Can't create Endpoint in ipstack: %v", err)
		}
		r.Complete(false)
		conn := gonet.NewConn(&wq, ep)

		target := getAddr(ep.Info().(*tcp.EndpointInfo).ID)

		tun.Add(adapters.NewSocket(target, conn, C.TUN, C.TCP))

	})
	ipstack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	// TODO: UDP Handler

	tl := &TunAdapter{
		tunfd:   tunfd,
		ipstack: ipstack,
		ifName:  linuxIfName,
	}
	log.Infoln("Tun adapter have interface name: %s", linuxIfName)

	return tl, nil

}

// Close close the TunAdapter
func (t *TunAdapter) Close() {
	if t.tunfd != -1 {
		syscall.Close(t.tunfd)
		t.tunfd = -1
	}
}

// IfName return the NIC name of tun
func (t *TunAdapter) IfName() string {
	if t.tunfd != -1 {
		return t.ifName
	}
	return ""
}

func getAddr(id stack.TransportEndpointID) socks5.Addr {
	ipv4 := id.LocalAddress.To4()

	// get the big-endian binary represent of port
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, id.LocalPort)

	if ipv4 != "" {
		addr := make([]byte, 1+net.IPv4len+2)
		addr[0] = socks5.AtypIPv4
		copy(addr[1:1+net.IPv4len], []byte(ipv4))
		addr[1+net.IPv4len], addr[1+net.IPv4len+1] = port[0], port[1]
		return addr
	} else {
		addr := make([]byte, 1+net.IPv6len+2)
		addr[0] = socks5.AtypIPv6
		copy(addr[1:1+net.IPv6len], []byte(id.LocalAddress))
		addr[1+net.IPv6len], addr[1+net.IPv6len+1] = port[0], port[1]
		return addr
	}

}
