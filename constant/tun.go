package constant

import (
	"net"
	"net/netip"
)

const (
	TunAddress       = "198.18.0.1"
	TunDnsAddress    = "198.18.0.2"
	TunDnsListen     = "198.18.0.2:53"
	TunDevName       = "clash0"
	tunBroadcastAddr = "198.18.255.255"
)

// ZeroTierFakeGatewayIp from
// https://github.com/zerotier/ZeroTierOne/blob/1.8.6/osdep/WindowsEthernetTap.cpp#L994
var ZeroTierFakeGatewayIp = netip.MustParseAddr("25.255.255.254")

var TunBroadcastAddr = net.ParseIP(tunBroadcastAddr)
var TunAutoRouteCidr = []string{
	// From "CIDR Ranges for Everything except RFC1918"
	// https://serverfault.com/questions/304781/cidr-ranges-for-everything-except-rfc1918

	//$ netmask -c 0.0.0.0:9.255.255.255
	"0.0.0.0/5",
	"8.0.0.0/7",
	//$ netmask -c 11.0.0.0:172.15.255.255
	"11.0.0.0/8",
	"12.0.0.0/6",
	"16.0.0.0/4",
	"32.0.0.0/3",
	"64.0.0.0/2",
	"128.0.0.0/3",
	"160.0.0.0/5",
	"168.0.0.0/6",
	"172.0.0.0/12",
	//$ netmask -c 172.32.0.0:192.167.255.255
	"172.32.0.0/11",
	"172.64.0.0/10",
	"172.128.0.0/9",
	"173.0.0.0/8",
	"174.0.0.0/7",
	"176.0.0.0/4",
	"192.0.0.0/9",
	"192.128.0.0/11",
	"192.160.0.0/13",
	//$ netmask -c 192.169.0.0:223.255.255.255
	"192.169.0.0/16",
	"192.170.0.0/15",
	"192.172.0.0/14",
	"192.176.0.0/12",
	"192.192.0.0/10",
	"193.0.0.0/8",
	"194.0.0.0/7",
	"196.0.0.0/6",
	"200.0.0.0/5",
	"208.0.0.0/4",
}

//var TunAutoRouteCidr = []string{
//	//"0.0.0.0/0",
//	"1.0.0.0/8",
//	"2.0.0.0/7",
//	"4.0.0.0/6",
//	"8.0.0.0/5",
//	"16.0.0.0/4",
//	"32.0.0.0/3",
//	"64.0.0.0/2",
//	"128.0.0.0/1",
//	"224.0.0.0/4",
//	"255.255.255.255/32",
//}
