package constant

import (
	"net"
)

const (
	TunAddress       = "198.18.0.1"
	TunDnsAddress    = "198.18.0.2"
	TunDnsListen     = "198.18.0.2:53"
	TunDevName       = "clash0"
	tunBroadcastAddr = "198.18.255.255"
)

var TunBroadcastAddr = net.IP(tunBroadcastAddr)
var TunAutoRouteCidr = []string{
	//"0.0.0.0/0",
	"1.0.0.0/8",
	"2.0.0.0/7",
	"4.0.0.0/6",
	"8.0.0.0/5",
	"16.0.0.0/4",
	"32.0.0.0/3",
	"64.0.0.0/2",
	"128.0.0.0/1",
	"224.0.0.0/4",
	"255.255.255.255/32",
}
