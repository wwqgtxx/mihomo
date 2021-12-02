package constant

import "net"

const (
	TunAddress       = "198.18.0.1"
	TunDnsAddress    = "198.18.0.2"
	TunDnsListen     = "0.0.0.0:53"
	tunBroadcastAddr = "198.18.255.255"
)

var TunBroadcastAddr = net.IP(tunBroadcastAddr)
