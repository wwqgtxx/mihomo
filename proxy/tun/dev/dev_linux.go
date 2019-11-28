// +build linux android

package dev

import (
	"errors"
	"net/url"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/google/netstack/tcpip/link/fdbased"
	stacktun "github.com/google/netstack/tcpip/link/tun"
	"github.com/google/netstack/tcpip/stack"
)

type tun struct {
	url       string
	name      string
	fd        int
	linkCache *stack.LinkEndpoint
}

// OpenTunDevice return a TunDevice according a URL
func OpenTunDevice(deviceURL url.URL) (TunDevice, error) {
	switch deviceURL.Scheme {
	case "dev":
		return tun{
			url: deviceURL.String(),
		}.openDeviceByName(deviceURL.Host)
	case "fd":
		fd, err := strconv.ParseInt(deviceURL.Host, 10, 32)
		if err != nil {
			return nil, err
		}
		return tun{
			url: deviceURL.String(),
		}.openDeviceByFd(int(fd))
	}

	return nil, errors.New("Unsupported device type " + deviceURL.Scheme)
}

func (t tun) Name() string {
	return t.name
}

func (t tun) URL() string {
	return t.url
}

func (t tun) AsLinkEndpoint() (result stack.LinkEndpoint, err error) {
	if t.linkCache != nil {
		return *t.linkCache, nil
	}

	mtu, err := t.getInterfaceMtu()

	if err != nil {
		return nil, errors.New("Unable to get device mtu")
	}

	result, err = fdbased.New(&fdbased.Options{
		FDs:            []int{t.fd},
		MTU:            mtu,
		EthernetHeader: false,
	})

	t.linkCache = &result

	return result, nil
}

func (t tun) Close() {
	syscall.Close(t.fd)
}

func (t tun) openDeviceByName(name string) (TunDevice, error) {
	fd, err := stacktun.Open(name)
	if err != nil {
		return nil, err
	}

	t.name = name
	t.fd = fd

	return t, nil
}

func (t tun) openDeviceByFd(fd int) (TunDevice, error) {
	var ifr struct {
		name  [16]byte
		flags uint16
		_     [22]byte
	}

	fd, err := syscall.Dup(fd)
	if err != nil {
		return nil, err
	}

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TUNGETIFF, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return nil, errno
	}

	if ifr.flags&syscall.IFF_TUN == 0 || ifr.flags&syscall.IFF_NO_PI == 0 {
		return nil, errors.New("Only tun device and no pi mode supported")
	}

	t.name = convertInterfaceName(ifr.name)
	t.fd = fd

	return t, nil
}

func (t tun) getInterfaceMtu() (uint32, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}

	defer syscall.Close(fd)

	var ifreq struct {
		name [16]byte
		mtu  int32
		_    [20]byte
	}

	copy(ifreq.name[:], t.name)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCGIFMTU, uintptr(unsafe.Pointer(&ifreq)))
	if errno != 0 {
		return 0, errno
	}

	return uint32(ifreq.mtu), nil
}

func convertInterfaceName(buf [16]byte) string {
	var n int

	for i, c := range buf {
		if c == 0 {
			n = i
			break
		}
	}

	return string(buf[:n])
}
