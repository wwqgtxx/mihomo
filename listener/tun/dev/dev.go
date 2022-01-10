package dev

import (
	"os/exec"
	"runtime"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

// TunDevice is cross-platform tun interface
type TunDevice interface {
	Name() string
	URL() string
	MTU() (int, error)
	IsClose() bool
	Close() error
	Read(buff []byte) (int, error)
	Write(buff []byte) (int, error)
}

func SetLinuxAutoRoute(autoRouteCidr []string) {
	log.Infoln("Tun adapter auto setting global route")
	for _, ipCidr := range autoRouteCidr {
		addLinuxSystemRoute(ipCidr)
	}
}

func RemoveLinuxAutoRoute(autoRouteCidr []string) {
	log.Infoln("Tun adapter removing global route")
	for _, ipCidr := range autoRouteCidr {
		delLinuxSystemRoute(ipCidr)
	}
}

func addLinuxSystemRoute(net string) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return
	}
	cmd := exec.Command("route", "add", "-net", net, "dev", C.TunDevName)
	if err := cmd.Run(); err != nil {
		log.Errorln("[auto route] Failed to add system route: %s, cmd: %s", err.Error(), cmd.String())
	}
}

func delLinuxSystemRoute(net string) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return
	}
	cmd := exec.Command("route", "delete", "-net", net, "dev", C.TunDevName)
	_ = cmd.Run()
	//if err := cmd.Run(); err != nil {
	//	log.Errorln("[auto route]Failed to delete system route: %s, cmd: %s", err.Error(), cmd.String())
	//}
}
