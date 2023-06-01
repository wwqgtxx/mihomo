package dns

import (
	"net"
)

func loadSystemResolver() (clients []dnsClient, err error) {
	nameservers, err := dnsReadConfig()
	if err != nil {
		return
	}
	servers := make([]NameServer, 0, len(nameservers))
	for _, addr := range nameservers {
		servers = append(servers, NameServer{
			Addr: net.JoinHostPort(addr, "53"),
			Net:  "udp",
		})
	}
	return transform(servers, nil), nil
}
