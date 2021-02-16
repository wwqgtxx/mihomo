package proxy

import (
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/proxy/http"
	"github.com/Dreamacro/clash/proxy/mixed"
	"github.com/Dreamacro/clash/proxy/redir"
	"github.com/Dreamacro/clash/proxy/shadowsocks"
	"github.com/Dreamacro/clash/proxy/socks"
	"github.com/Dreamacro/clash/proxy/tunnel"
)

var (
	allowLan    = false
	bindAddress = "*"

	socksListener          *socks.SockListener
	socksUDPListener       *socks.SockUDPListener
	httpListener           *http.HttpListener
	redirListener          *redir.RedirListener
	redirUDPListener       *redir.RedirUDPListener
	tproxyListener         *redir.TProxyListener
	tproxyUDPListener      *redir.RedirUDPListener
	mixedListener          *mixed.MixedListener
	mixedUDPLister         *socks.SockUDPListener
	mixECListener          *mixed.MixECListener
	mixECUDPLister         *socks.SockUDPListener
	shadowSocksListener    *shadowsocks.ShadowSocksListener
	shadowSocksUDPListener *shadowsocks.ShadowSocksUDPListener
	tcpTunListener         *tunnel.TcpTunListener
	udpTunListener         *tunnel.UdpTunListener

	// lock for recreate function
	socksMux  sync.Mutex
	httpMux   sync.Mutex
	redirMux  sync.Mutex
	tproxyMux sync.Mutex
	mixedMux  sync.Mutex
	mixECMux  sync.Mutex
	ssMux     sync.Mutex
	tcpTunMux sync.Mutex
	udpTunMux sync.Mutex
)

type Ports struct {
	Port              int    `json:"port"`
	SocksPort         int    `json:"socks-port"`
	RedirPort         int    `json:"redir-port"`
	MixedPort         int    `json:"mixed-port"`
	MixECPort         int    `json:"mixec-port"`
	TProxyPort        int    `json:"tproxy-port"`
	ShadowSocksConfig string `json:"ss-config"`
	TcpTunConfig      string `json:"tcptun-config"`
	UdpTunConfig      string `json:"udptun-config"`
}

func AllowLan() bool {
	return allowLan
}

func BindAddress() string {
	return bindAddress
}

func SetAllowLan(al bool) {
	allowLan = al
}

func SetBindAddress(host string) {
	bindAddress = host
}

func ReCreateHTTP(port int) error {
	httpMux.Lock()
	defer httpMux.Unlock()

	addr := genAddr(bindAddress, port, allowLan)

	if httpListener != nil {
		if httpListener.Address() == addr {
			return nil
		}
		httpListener.Close()
		httpListener = nil
	}

	if portIsZero(addr) {
		return nil
	}

	var err error
	httpListener, err = http.NewHttpProxy(addr)
	if err != nil {
		return err
	}

	return nil
}

func ReCreateSocks(port int) error {
	socksMux.Lock()
	defer socksMux.Unlock()

	addr := genAddr(bindAddress, port, allowLan)

	shouldTCPIgnore := false
	shouldUDPIgnore := false

	if socksListener != nil {
		if socksListener.Address() != addr {
			socksListener.Close()
			socksListener = nil
		} else {
			shouldTCPIgnore = true
		}
	}

	if socksUDPListener != nil {
		if socksUDPListener.Address() != addr {
			socksUDPListener.Close()
			socksUDPListener = nil
		} else {
			shouldUDPIgnore = true
		}
	}

	if shouldTCPIgnore && shouldUDPIgnore {
		return nil
	}

	if portIsZero(addr) {
		return nil
	}

	tcpListener, err := socks.NewSocksProxy(addr)
	if err != nil {
		return err
	}

	udpListener, err := socks.NewSocksUDPProxy(addr)
	if err != nil {
		tcpListener.Close()
		return err
	}

	socksListener = tcpListener
	socksUDPListener = udpListener

	return nil
}

func ReCreateShadowSocks(shadowSocksConfig string) error {
	ssMux.Lock()
	defer ssMux.Unlock()

	shouldTCPIgnore := false
	shouldUDPIgnore := false

	if shadowSocksListener != nil {
		if shadowSocksListener.Config() != shadowSocksConfig {
			shadowSocksListener.Close()
			shadowSocksListener = nil
		} else {
			shouldTCPIgnore = true
		}
	}

	if shadowSocksUDPListener != nil {
		if shadowSocksUDPListener.Config() != shadowSocksConfig {
			shadowSocksUDPListener.Close()
			shadowSocksUDPListener = nil
		} else {
			shouldUDPIgnore = true
		}
	}

	if shouldTCPIgnore && shouldUDPIgnore {
		return nil
	}

	if len(shadowSocksConfig) == 0 {
		return nil
	}

	tcpListener, err := shadowsocks.NewShadowSocksProxy(shadowSocksConfig)
	if err != nil {
		return err
	}

	udpListener, err := shadowsocks.NewShadowSocksUDPProxy(shadowSocksConfig)
	if err != nil {
		return err
	}

	shadowSocksListener = tcpListener
	shadowSocksUDPListener = udpListener

	return nil
}

func ReCreateRedir(port int) error {
	redirMux.Lock()
	defer redirMux.Unlock()

	addr := genAddr(bindAddress, port, allowLan)

	if redirListener != nil {
		if redirListener.Address() == addr {
			return nil
		}
		redirListener.Close()
		redirListener = nil
	}

	if redirUDPListener != nil {
		if redirUDPListener.Address() == addr {
			return nil
		}
		redirUDPListener.Close()
		redirUDPListener = nil
	}

	if portIsZero(addr) {
		return nil
	}

	var err error
	redirListener, err = redir.NewRedirProxy(addr)
	if err != nil {
		return err
	}

	redirUDPListener, err = redir.NewRedirUDPProxy(addr)
	if err != nil {
		log.Warnln("Failed to start Redir UDP Listener: %s", err)
	}

	return nil
}

func ReCreateTcpTun(config string) error {
	tcpTunMux.Lock()
	defer tcpTunMux.Unlock()
	shouldIgnore := false

	if tcpTunListener != nil {
		if tcpTunListener.Config() != config {
			shadowSocksListener.Close()
			shadowSocksListener = nil
		} else {
			shouldIgnore = true
		}
	}

	if shouldIgnore {
		return nil
	}

	tcpListener, err := tunnel.NewTcpTunProxy(config)
	if err != nil {
		return err
	}

	tcpTunListener = tcpListener

	return nil
}

func ReCreateUdpTun(config string) error {
	udpTunMux.Lock()
	defer udpTunMux.Unlock()
	shouldIgnore := false

	if udpTunListener != nil {
		if udpTunListener.Config() != config {
			shadowSocksListener.Close()
			shadowSocksListener = nil
		} else {
			shouldIgnore = true
		}
	}

	if shouldIgnore {
		return nil
	}

	udpListener, err := tunnel.NewUdpTunProxy(config)
	if err != nil {
		return err
	}

	udpTunListener = udpListener

	return nil
}

func ReCreateTProxy(port int) error {
	tproxyMux.Lock()
	defer tproxyMux.Unlock()

	addr := genAddr(bindAddress, port, allowLan)

	if tproxyListener != nil {
		if tproxyListener.Address() == addr {
			return nil
		}
		tproxyListener.Close()
		tproxyListener = nil
	}

	if tproxyUDPListener != nil {
		if tproxyUDPListener.Address() == addr {
			return nil
		}
		tproxyUDPListener.Close()
		tproxyUDPListener = nil
	}

	if portIsZero(addr) {
		return nil
	}

	var err error
	tproxyListener, err = redir.NewTProxy(addr)
	if err != nil {
		return err
	}

	tproxyUDPListener, err = redir.NewRedirUDPProxy(addr)
	if err != nil {
		log.Warnln("Failed to start TProxy UDP Listener: %s", err)
	}

	return nil
}

func ReCreateMixed(port int) error {
	mixedMux.Lock()
	defer mixedMux.Unlock()

	addr := genAddr(bindAddress, port, allowLan)

	shouldTCPIgnore := false
	shouldUDPIgnore := false

	if mixedListener != nil {
		if mixedListener.Address() != addr {
			mixedListener.Close()
			mixedListener = nil
		} else {
			shouldTCPIgnore = true
		}
	}
	if mixedUDPLister != nil {
		if mixedUDPLister.Address() != addr {
			mixedUDPLister.Close()
			mixedUDPLister = nil
		} else {
			shouldUDPIgnore = true
		}
	}

	if shouldTCPIgnore && shouldUDPIgnore {
		return nil
	}

	if portIsZero(addr) {
		return nil
	}

	var err error
	mixedListener, err = mixed.NewMixedProxy(addr)
	if err != nil {
		return err
	}

	mixedUDPLister, err = socks.NewSocksUDPProxy(addr)
	if err != nil {
		mixedListener.Close()
		return err
	}

	return nil
}

func ReCreateMixEC(port int) error {
	mixECMux.Lock()
	defer mixECMux.Unlock()

	addr := genAddr(bindAddress, port, allowLan)

	shouldTCPIgnore := false
	shouldUDPIgnore := false

	if mixECListener != nil {
		if mixECListener.Address() != addr {
			mixECListener.Close()
			mixECListener = nil
		} else {
			shouldTCPIgnore = true
		}
	}
	if mixECUDPLister != nil {
		if mixECUDPLister.Address() != addr {
			mixECUDPLister.Close()
			mixECUDPLister = nil
		} else {
			shouldUDPIgnore = true
		}
	}

	if shouldTCPIgnore && shouldUDPIgnore {
		return nil
	}

	if portIsZero(addr) {
		return nil
	}

	var err error
	mixECListener, err = mixed.NewMixECProxy(addr)
	if err != nil {
		return err
	}

	mixECUDPLister, err = socks.NewSocksUDPProxy(addr)
	if err != nil {
		mixECListener.Close()
		return err
	}

	return nil
}

// GetPorts return the ports of proxy servers
func GetPorts() *Ports {
	ports := &Ports{}

	if httpListener != nil {
		_, portStr, _ := net.SplitHostPort(httpListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.Port = port
	}

	if socksListener != nil {
		_, portStr, _ := net.SplitHostPort(socksListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.SocksPort = port
	}

	if redirListener != nil {
		_, portStr, _ := net.SplitHostPort(redirListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.RedirPort = port
	}

	if tproxyListener != nil {
		_, portStr, _ := net.SplitHostPort(tproxyListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.TProxyPort = port
	}

	if mixedListener != nil {
		_, portStr, _ := net.SplitHostPort(mixedListener.Address())
		port, _ := strconv.Atoi(portStr)
		ports.MixedPort = port
	}

	if shadowSocksListener != nil {
		ports.ShadowSocksConfig = shadowSocksListener.Config()
	}

	if tcpTunListener != nil {
		ports.TcpTunConfig = tcpTunListener.Config()
	}

	if udpTunListener != nil {
		ports.UdpTunConfig = udpTunListener.Config()
	}

	return ports
}

func portIsZero(addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	if port == "0" || port == "" || err != nil {
		return true
	}
	return false
}

func genAddr(host string, port int, allowLan bool) string {
	if allowLan {
		if host == "*" {
			return fmt.Sprintf(":%d", port)
		} else {
			return fmt.Sprintf("%s:%d", host, port)
		}
	}

	return fmt.Sprintf("127.0.0.1:%d", port)
}
