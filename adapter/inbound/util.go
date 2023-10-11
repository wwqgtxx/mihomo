package inbound

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/socks5"
)

func parseSocksAddr(target socks5.Addr) *C.Metadata {
	metadata := &C.Metadata{}

	switch target[0] {
	case socks5.AtypDomainName:
		// trim for FQDN
		metadata.Host = strings.TrimRight(string(target[2:2+target[1]]), ".")
		metadata.DstPort = uint16((int(target[2+target[1]]) << 8) | int(target[2+target[1]+1]))
	case socks5.AtypIPv4:
		metadata.DstIP, _ = netip.AddrFromSlice(target[1 : 1+net.IPv4len])
		metadata.DstPort = uint16((int(target[1+net.IPv4len]) << 8) | int(target[1+net.IPv4len+1]))
	case socks5.AtypIPv6:
		metadata.DstIP, _ = netip.AddrFromSlice(target[1 : 1+net.IPv6len])
		metadata.DstPort = uint16((int(target[1+net.IPv6len]) << 8) | int(target[1+net.IPv6len+1]))
	}

	return metadata
}

func parseHTTPAddr(request *http.Request) *C.Metadata {
	host := request.URL.Hostname()
	port := request.URL.Port()
	if port == "" {
		port = "80"
	}

	// trim FQDN (#737)
	host = strings.TrimRight(host, ".")

	var uint16Port uint16
	if port, err := strconv.ParseUint(port, 10, 16); err == nil {
		uint16Port = uint16(port)
	}

	metadata := &C.Metadata{
		NetWork: C.TCP,
		Host:    host,
		DstPort: uint16Port,
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		metadata.DstIP = ip
	}

	return metadata
}

func parseAddr(addr net.Addr) netip.AddrPort {
	// Filter when net.Addr interface is nil
	if addr == nil {
		return netip.AddrPort{}
	}
	if addr, ok := addr.(interface{ RawAddr() net.Addr }); ok {
		if rawAddr := addr.RawAddr(); rawAddr != nil {
			return parseAddr(rawAddr)
		}
	}
	if addr, ok := addr.(interface{ AddrPort() netip.AddrPort }); ok {
		return addr.AddrPort()
	}
	addrStr := addr.String()
	host, port, err := net.SplitHostPort(addrStr)
	if err != nil {
		return netip.AddrPort{}
	}

	var uint16Port uint16
	if port, err := strconv.ParseUint(port, 10, 16); err == nil {
		uint16Port = uint16(port)
	}

	ip, _ := netip.ParseAddr(host)
	return netip.AddrPortFrom(ip, uint16Port)
}
