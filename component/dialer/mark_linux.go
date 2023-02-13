//go:build linux

package dialer

import (
	"context"
	"net"
	"net/netip"
	"syscall"
)

func bindMarkToDialer(mark int, dialer *net.Dialer, _ string, _ netip.Addr) {
	addControlToDialer(dialer, bindMarkToControl(mark))
}

func bindMarkToListenConfig(mark int, lc *net.ListenConfig, _, address string) {
	addControlToListenConfig(lc, bindMarkToControl(mark))
}

func bindMarkToControl(mark int) controlFn {
	return func(ctx context.Context, network, address string, c syscall.RawConn) (err error) {

		ipStr, _, err := net.SplitHostPort(address)
		if err == nil {
			ip := net.ParseIP(ipStr)
			if ip != nil && !ip.IsGlobalUnicast() {
				return
			}
		}

		var innerErr error
		err = c.Control(func(fd uintptr) {
			innerErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
		})
		if innerErr != nil {
			err = innerErr
		}
		return
	}
}
