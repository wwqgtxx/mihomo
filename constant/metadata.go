package constant

import (
	"encoding/json"
	"net"
	"net/netip"
	"strconv"

	"github.com/Dreamacro/clash/transport/socks5"
)

// Socks addr type
const (
	TCP NetWork = iota
	UDP
	ALLNet
	InvalidNet = 0xff
)

const (
	HTTP Type = iota
	HTTPCONNECT
	SOCKS4
	SOCKS5
	SHADOWSOCKS
	VMESS
	REDIR
	TPROXY
	TUNNEL
	MTPROXY
	TUN
	TUIC
	INNER
	DNS
	PROVIDER
)

type NetWork int

func (n NetWork) String() string {
	switch n {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	case ALLNet:
		return "all"
	default:
		return "invalid"
	}
}

func (n NetWork) MarshalJSON() ([]byte, error) {
	return json.Marshal(n.String())
}

type Type int

func (t Type) String() string {
	switch t {
	case HTTP:
		return "HTTP"
	case HTTPCONNECT:
		return "HTTP Connect"
	case SOCKS4:
		return "Socks4"
	case SOCKS5:
		return "Socks5"
	case SHADOWSOCKS:
		return "ShadowSocks"
	case VMESS:
		return "Vmess"
	case REDIR:
		return "Redir"
	case TPROXY:
		return "TProxy"
	case TUNNEL:
		return "Tunnel"
	case MTPROXY:
		return "MTProxy"
	case TUN:
		return "TUN"
	case TUIC:
		return "TUIC"
	case INNER:
		return "Inner"
	case DNS:
		return "DNS"
	case PROVIDER:
		return "Provider"
	default:
		return "Unknown"
	}
}

func (t Type) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// Metadata is used to store connection address
type Metadata struct {
	NetWork      NetWork    `json:"network"`
	Type         Type       `json:"type"`
	SrcIP        netip.Addr `json:"sourceIP"`
	DstIP        netip.Addr `json:"destinationIP"`
	SrcPort      string     `json:"sourcePort"`
	DstPort      string     `json:"destinationPort"`
	InIP         netip.Addr `json:"inboundIP"`
	InPort       string     `json:"inboundPort"`
	InName       string     `json:"inboundName"`
	Host         string     `json:"host"`
	DNSMode      DNSMode    `json:"dnsMode"`
	Process      string     `json:"process"`
	ProcessPath  string     `json:"processPath"`
	SpecialProxy string     `json:"specialProxy"`
	SpecialRules string     `json:"specialRules"`
}

func (m *Metadata) RemoteAddress() string {
	return net.JoinHostPort(m.String(), m.DstPort)
}

func (m *Metadata) SourceAddress() string {
	if !m.SrcIP.IsValid() {
		return m.Type.String()
	}
	return net.JoinHostPort(m.SrcIP.String(), m.SrcPort)
}

func (m *Metadata) AddrType() int {
	switch true {
	case m.Host != "" || !m.DstIP.IsValid():
		return socks5.AtypDomainName
	case m.DstIP.Is4():
		return socks5.AtypIPv4
	default:
		return socks5.AtypIPv6
	}
}

func (m *Metadata) Resolved() bool {
	return m.DstIP.IsValid()
}

// Pure is used to solve unexpected behavior
// when dialing proxy connection in DNSMapping mode.
func (m *Metadata) Pure() *Metadata {
	if (m.DNSMode == DNSMapping || m.DNSMode == DNSHosts) && m.DstIP.IsValid() {
		copy := *m
		copy.Host = ""
		return &copy
	}

	return m
}

func (m *Metadata) AddrPort() netip.AddrPort {
	port, _ := strconv.ParseUint(m.DstPort, 10, 16)
	return netip.AddrPortFrom(m.DstIP.Unmap(), uint16(port))
}

func (m *Metadata) UDPAddr() *net.UDPAddr {
	if m.NetWork != UDP || !m.DstIP.IsValid() {
		return nil
	}
	return net.UDPAddrFromAddrPort(m.AddrPort())
}

func (m *Metadata) String() string {
	if m.Host != "" {
		return m.Host
	} else if m.DstIP.IsValid() {
		return m.DstIP.String()
	} else {
		return "<nil>"
	}
}

func (m *Metadata) Valid() bool {
	return m.Host != "" || m.DstIP.IsValid()
}

func (m *Metadata) SetRemoteAddress(rawAddress string) error {
	host, port, err := net.SplitHostPort(rawAddress)
	if err != nil {
		return err
	}

	if ip, err := netip.ParseAddr(host); err != nil {
		m.Host = host
		m.DstIP = netip.Addr{}
	} else {
		m.Host = ""
		m.DstIP = ip.Unmap()
	}
	m.DstPort = port

	return nil
}
