package outbound

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"

	"github.com/Dreamacro/clash/component/resolver"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/transport/socks5"
)

func serializesSocksAddr(metadata *C.Metadata) []byte {
	var buf [][]byte
	addrType := metadata.AddrType()
	aType := uint8(addrType)
	p := uint(metadata.DstPort)
	port := []byte{uint8(p >> 8), uint8(p & 0xff)}
	switch addrType {
	case socks5.AtypDomainName:
		lenM := uint8(len(metadata.Host))
		host := []byte(metadata.Host)
		buf = [][]byte{{aType, lenM}, host, port}
	case socks5.AtypIPv4:
		host := metadata.DstIP.AsSlice()
		buf = [][]byte{{aType}, host, port}
	case socks5.AtypIPv6:
		host := metadata.DstIP.AsSlice()
		buf = [][]byte{{aType}, host, port}
	}
	return bytes.Join(buf, nil)
}

func resolveUDPAddr(ctx context.Context, network, address string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	ip, err := resolver.ResolveIPWithResolver(ctx, host, resolver.DialerResolver)
	if err != nil {
		return nil, err
	}
	return net.ResolveUDPAddr(network, net.JoinHostPort(ip.String(), port))
}

func safeConnClose(c net.Conn, err error) {
	if err != nil && c != nil {
		_ = c.Close()
	}
}

var rateStringRegexp = regexp.MustCompile(`^(\d+)\s*([KMGT]?)([Bb])ps$`)

func stringToBps(s string) uint64 {
	if s == "" {
		return 0
	}

	// when have not unit, use Mbps
	if v, err := strconv.Atoi(s); err == nil {
		return stringToBps(fmt.Sprintf("%d Mbps", v))
	}

	m := rateStringRegexp.FindStringSubmatch(s)
	if m == nil {
		return 0
	}
	var n uint64
	switch m[2] {
	case "K":
		n = 1 << 10
	case "M":
		n = 1 << 20
	case "G":
		n = 1 << 30
	case "T":
		n = 1 << 40
	default:
		n = 1
	}
	v, _ := strconv.ParseUint(m[1], 10, 64)
	n = v * n
	if m[3] == "b" {
		// Bits, need to convert to bytes
		n = n >> 3
	}
	return n
}
