package provider

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/inner_dialer"
	C "github.com/metacubex/mihomo/constant"
	types "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
)

var remoteDialer = inner_dialer.NewDialer(C.PROVIDER)

type FileVehicle struct {
	path string
}

func (f *FileVehicle) Type() types.VehicleType {
	return types.File
}

func (f *FileVehicle) Path() string {
	return f.path
}

func (f *FileVehicle) Read() ([]byte, error) {
	return os.ReadFile(f.path)
}

func NewFileVehicle(path string) *FileVehicle {
	return &FileVehicle{path: path}
}

type HTTPVehicle struct {
	url  string
	path string
}

func (h *HTTPVehicle) Type() types.VehicleType {
	return types.HTTP
}

func (h *HTTPVehicle) Path() string {
	return h.path
}

func (h *HTTPVehicle) Read() (buf []byte, err error) {
	type DC func(ctx context.Context, network, address string) (net.Conn, error)
	innerDailContext := remoteDialer.DialContext
	defaultDailContext := func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, address)
	}

	read := func(dc DC) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
		defer cancel()

		uri, err := url.Parse(h.url)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequest(http.MethodGet, uri.String(), nil)
		if err != nil {
			return nil, err
		}

		if user := uri.User; user != nil {
			password, _ := user.Password()
			req.SetBasicAuth(user.Username(), password)
		}

		req.Header.Set("User-Agent", "mihomo")

		req = req.WithContext(ctx)

		transport := &http.Transport{
			// from http.DefaultTransport
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DialContext:           dc,
		}

		client := http.Client{Transport: transport}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		buf, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		return buf, nil
	}

	buf, err = read(innerDailContext)
	if err != nil {
		log.Errorln("[Provider] fetch from inner error: %s, fallback to direct", err)
		buf, err = read(defaultDailContext)
	}

	return
}

func NewHTTPVehicle(url string, path string) *HTTPVehicle {
	return &HTTPVehicle{url, path}
}
