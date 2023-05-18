package vmess

import (
	"context"
	"crypto/tls"
	"net"
)

type TLSConfig struct {
	Host           string
	SkipCertVerify bool
	NextProtos     []string
}

func StreamTLSConn(ctx context.Context, conn net.Conn, cfg *TLSConfig) (net.Conn, error) {
	tlsConfig := &tls.Config{
		ServerName:         cfg.Host,
		InsecureSkipVerify: cfg.SkipCertVerify,
		NextProtos:         cfg.NextProtos,
	}

	tlsConn := tls.Client(conn, tlsConfig)

	err := tlsConn.HandshakeContext(ctx)
	return tlsConn, err
}
