package tun

import (
	"errors"
	"fmt"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/tun/dev"
	"github.com/Dreamacro/clash/listener/tun/ipstack"
	"github.com/Dreamacro/clash/listener/tun/ipstack/gvisor"
	"github.com/Dreamacro/clash/log"
)

// New create TunAdapter
func New(conf config.Tun, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) (ipstack.TunAdapter, error) {
	tunAddress := C.TunAddress
	var tunAdapter ipstack.TunAdapter

	device, err := dev.OpenTunDevice(tunAddress, conf.AutoRoute)
	if err != nil {
		return nil, fmt.Errorf("can't open tun: %v", err)
	}

	mtu, err := device.MTU()
	if err != nil {
		_ = device.Close()
		return nil, errors.New("unable to get device mtu")
	}

	tunAdapter, err = gvisor.NewAdapter(device, tunAddress, conf, tcpIn, udpIn)

	if err != nil {
		_ = device.Close()
		return nil, err
	}

	log.Infoln("Tun adapter listening at: %s(%s), mtu: %d, auto route: %v, ip stack: %s",
		device.Name(), tunAddress, mtu, tunAdapter.AutoRoute(), tunAdapter.Stack())
	return tunAdapter, nil
}
