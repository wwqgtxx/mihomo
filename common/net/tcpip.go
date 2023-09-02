package net

import (
	"net"
	"time"
)

var KeepAliveInterval time.Duration

func TCPKeepAlive(c net.Conn) {
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(KeepAliveInterval * time.Second)
	}
}
