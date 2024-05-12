package vmess

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/metacubex/mihomo/component/ca"
)

type TLSConfig struct {
	Host           string
	SkipCertVerify bool
	FingerPrint    string
	NextProtos     []string
}

func StreamTLSConn(ctx context.Context, conn net.Conn, cfg *TLSConfig) (net.Conn, error) {
	tlsConfig := &tls.Config{
		ServerName:         cfg.Host,
		InsecureSkipVerify: cfg.SkipCertVerify,
		NextProtos:         cfg.NextProtos,
	}

	var err error
	tlsConfig, err = ca.GetSpecifiedFingerprintTLSConfig(tlsConfig, cfg.FingerPrint)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(conn, tlsConfig)

	err = tlsConn.HandshakeContext(ctx)
	return tlsConn, err
}
