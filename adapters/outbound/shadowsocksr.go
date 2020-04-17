package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/wwqgtxx/clashr/component/dialer"
	"github.com/wwqgtxx/clashr/component/socks5"
	C "github.com/wwqgtxx/clashr/constant"
	"github.com/wwqgtxx/gossr"
	"github.com/wwqgtxx/gossr/obfs"
	"github.com/wwqgtxx/gossr/protocol"
	"github.com/wwqgtxx/gossr/ssr"
)

type ShadowsocksR struct {
	*Base
	server string
	cipher *gossr.StreamCipher

	//ssrquery     *url.URL
	ssrop        ShadowsocksROption
	ObfsData     interface{}
	ProtocolData interface{}
}

type ShadowsocksROption struct {
	Name          string `proxy:"name"`
	Server        string `proxy:"server"`
	Port          int    `proxy:"port"`
	Password      string `proxy:"password"`
	Cipher        string `proxy:"cipher"`
	Protocol      string `proxy:"protocol"`
	ProtocolParam string `proxy:"protocolparam"`
	Obfs          string `proxy:"obfs"`
	ObfsParam     string `proxy:"obfsparam"`
	Udp           bool   `proxy:"udp,omitempty"`
}

func (ssrins *ShadowsocksR) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	ssrop := ssrins.ssrop

	conn, err := dialer.DialContext(ctx, "tcp", ssrins.server)
	if err != nil {
		return nil, err
	}

	dstcon := gossr.NewSSTCPConn(conn, ssrins.cipher.Copy())
	if dstcon.Conn == nil || dstcon.RemoteAddr() == nil {
		return nil, errors.New("nil connection")
	}

	rs := strings.Split(dstcon.RemoteAddr().String(), ":")
	port, _ := strconv.Atoi(rs[1])

	if strings.HasSuffix(ssrop.Obfs, "_compatible") {
		ssrop.Obfs = strings.ReplaceAll(ssrop.Obfs, "_compatible", "")
	}
	dstcon.IObfs, err = obfs.NewObfs(ssrop.Obfs)
	if err != nil {
		return nil, err
	}
	obfsServerInfo := &ssr.ServerInfoForObfs{
		Host:   rs[0],
		Port:   uint16(port),
		TcpMss: 1460,
		Param:  ssrop.ObfsParam,
	}
	dstcon.IObfs.SetServerInfo(obfsServerInfo)

	if strings.HasSuffix(ssrop.Protocol, "_compatible") {
		ssrop.Protocol = strings.ReplaceAll(ssrop.Protocol, "_compatible", "")
	}
	dstcon.IProtocol, err = protocol.NewProtocol(ssrop.Protocol)
	if err != nil {
		return nil, err
	}
	protocolServerInfo := &ssr.ServerInfoForObfs{
		Host:   rs[0],
		Port:   uint16(port),
		TcpMss: 1460,
		Param:  ssrop.ProtocolParam,
	}
	dstcon.IProtocol.SetServerInfo(protocolServerInfo)

	if ssrins.ObfsData == nil {
		ssrins.ObfsData = dstcon.IObfs.GetData()
	}
	dstcon.IObfs.SetData(ssrins.ObfsData)

	if ssrins.ProtocolData == nil {
		ssrins.ProtocolData = dstcon.IProtocol.GetData()
	}
	dstcon.IProtocol.SetData(ssrins.ProtocolData)

	if _, err := dstcon.Write(serializesSocksAddr(metadata)); err != nil {
		_ = dstcon.Close()
		return nil, err
	}
	return NewConn(dstcon, ssrins), err

}

func NewShadowsocksR(ssrop ShadowsocksROption) (*ShadowsocksR, error) {
	server := net.JoinHostPort(ssrop.Server, strconv.Itoa(ssrop.Port))
	ciph, err := gossr.NewStreamCipher(ssrop.Cipher, ssrop.Password)
	if err != nil {
		return nil, err
	}
	return &ShadowsocksR{
		Base: &Base{
			name: ssrop.Name,
			tp:   C.ShadowsocksR,
			udp:  ssrop.Udp,
		},
		server: server,
		cipher: ciph,
		//ssrquery: u,
		ssrop: ssrop,
	}, nil
}

func (ssrins *ShadowsocksR) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"type": ssrins.Type().String(),
	})
}

func (ssrins *ShadowsocksR) DialUDP(metadata *C.Metadata) (pac C.PacketConn, err error) {
	pc, err := dialer.ListenPacket("udp", "")
	if err != nil {
		return nil, err
	}

	addr, err := resolveUDPAddr("udp", ssrins.server)
	if err != nil {
		return nil, err
	}

	pc = gossr.NewSSUDPConn(pc, ssrins.cipher.Copy())
	dstcon := pc.(*gossr.PacketConn)
	ssrop := ssrins.ssrop
	if strings.HasSuffix(ssrop.Protocol, "_compatible") {
		ssrop.Protocol = strings.ReplaceAll(ssrop.Protocol, "_compatible", "")
	}
	dstcon.IProtocol, err = protocol.NewProtocol(ssrop.Protocol)
	if err != nil {
		return nil, err
	}
	protocolServerInfo := &ssr.ServerInfoForObfs{
		Host:   addr.IP.String(),
		Port:   uint16(addr.Port),
		TcpMss: 1460,
		Param:  ssrop.ProtocolParam,
	}
	dstcon.IProtocol.SetServerInfo(protocolServerInfo)

	return newPacketConn(&ssrUDPConn{PacketConn: pc, rAddr: addr}, ssrins), nil
}

type ssrUDPConn struct {
	net.PacketConn
	rAddr net.Addr
}

func (uc *ssrUDPConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	packet, err := socks5.EncodeUDPPacket(socks5.ParseAddrToSocksAddr(addr), b)
	if err != nil {
		return
	}
	return uc.PacketConn.WriteTo(packet[3:], uc.rAddr)
}

func (uc *ssrUDPConn) WriteWithMetadata(p []byte, metadata *C.Metadata) (n int, err error) {
	packet, err := socks5.EncodeUDPPacket(socks5.ParseAddr(metadata.RemoteAddress()), p)
	if err != nil {
		return
	}
	n, err = uc.PacketConn.WriteTo(packet[3:], uc.rAddr)
	return
}

func (uc *ssrUDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, e := uc.PacketConn.ReadFrom(b)
	if e != nil {
		return 0, nil, e
	}

	addr := socks5.SplitAddr(b[:n])
	if addr == nil {
		return 0, nil, errors.New("parse addr error")
	}

	udpAddr := addr.UDPAddr()
	if udpAddr == nil {
		return 0, nil, errors.New("parse addr error")
	}

	copy(b, b[len(addr):])
	return n - len(addr), udpAddr, e
}
