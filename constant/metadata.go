package constant

import (
	"encoding/json"
	"fmt"
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
	HYSTERIA2
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
	case HYSTERIA2:
		return "Hysteria2"
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

func ParseType(t string) (*Type, error) {
	var res Type
	switch t {
	case "HTTP":
		res = HTTP
	case "HTTPCONNECT":
		res = HTTPCONNECT
	case "SOCKS4":
		res = SOCKS4
	case "SOCKS5":
		res = SOCKS5
	case "SHADOWSOCKS":
		res = SHADOWSOCKS
	case "VMESS":
		res = VMESS
	case "REDIR":
		res = REDIR
	case "TPROXY":
		res = TPROXY
	case "TUNNEL":
		res = TUNNEL
	case "TUN":
		res = TUN
	case "TUIC":
		res = TUIC
	case "HYSTERIA2":
		res = HYSTERIA2
	case "INNER":
		res = INNER
	default:
		return nil, fmt.Errorf("unknown type: %s", t)
	}
	return &res, nil
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
	SrcPort      uint16     `json:"sourcePort,string"`      // `,string` is used to compatible with old version json output
	DstPort      uint16     `json:"destinationPort,string"` // `,string` is used to compatible with old version json output
	InIP         netip.Addr `json:"inboundIP"`
	InPort       uint16     `json:"inboundPort,string"` // `,string` is used to compatible with old version json output
	InName       string     `json:"inboundName"`
	InUser       string     `json:"inboundUser"`
	Host         string     `json:"host"`
	DNSMode      DNSMode    `json:"dnsMode"`
	Process      string     `json:"process"`
	ProcessPath  string     `json:"processPath"`
	SpecialProxy string     `json:"specialProxy"`
	SpecialRules string     `json:"specialRules"`
	// Only domain rule
	SniffHost string `json:"sniffHost"`
}

func (m *Metadata) RemoteAddress() string {
	return net.JoinHostPort(m.String(), strconv.FormatUint(uint64(m.DstPort), 10))
}

func (m *Metadata) SourceAddress() string {
	if !m.SrcIP.IsValid() {
		return m.Type.String()
	}
	return net.JoinHostPort(m.SrcIP.String(), strconv.FormatUint(uint64(m.SrcPort), 10))
}

func (m *Metadata) SourceDetail() string {
	switch {
	case m.Process != "":
		return fmt.Sprintf("%s(%s)", m.SourceAddress(), m.Process)
	default:
		return fmt.Sprintf("%s", m.SourceAddress())
	}
}

func (m *Metadata) SourceValid() bool {
	return m.SrcPort != 0 && m.SrcIP.IsValid()
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

func (m *Metadata) RuleHost() string {
	if len(m.SniffHost) == 0 {
		return m.Host
	} else {
		return m.SniffHost
	}
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
	return netip.AddrPortFrom(m.DstIP.Unmap(), m.DstPort)
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

	var uint16Port uint16
	if port, err := strconv.ParseUint(port, 10, 16); err == nil {
		uint16Port = uint16(port)
	}

	if ip, err := netip.ParseAddr(host); err != nil {
		m.Host = host
		m.DstIP = netip.Addr{}
	} else {
		m.Host = ""
		m.DstIP = ip.Unmap()
	}
	m.DstPort = uint16Port

	return nil
}
