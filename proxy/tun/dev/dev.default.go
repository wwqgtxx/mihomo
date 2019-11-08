// +build !linux,!android

package dev

import (
	"errors"
	"runtime"

	"net/url"
)

func OpenTunDevice(_ url.URL) (TunDevice, error) {
	return nil, errors.New("Unsupported platform " + runtime.GOOS)
}
