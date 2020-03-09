// +build !amd64,!arm64,!mips64

package tun

import (
	"errors"
	"runtime"
)

func NewTunProxy(deviceURL string) (TunAdapter, error) {
	return nil, errors.New("Unsupported platform " + runtime.GOOS + "/" + runtime.GOARCH)

}
