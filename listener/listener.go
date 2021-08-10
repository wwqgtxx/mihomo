package proxy

import (
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/Dreamacro/clash/adapter/inbound"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/http"
	"github.com/Dreamacro/clash/listener/mixec"
	"github.com/Dreamacro/clash/listener/mixed"
	"github.com/Dreamacro/clash/listener/mtproxy"
	"github.com/Dreamacro/clash/listener/redir"
	"github.com/Dreamacro/clash/listener/shadowsocks"
	"github.com/Dreamacro/clash/listener/socks"
	"github.com/Dreamacro/clash/listener/tproxy"
	"github.com/Dreamacro/clash/listener/tunnel"
	"github.com/Dreamacro/clash/log"
)

var (
	allowLan    = false
	bindAddress = "*"

	socksListener       *socks.Listener
	socksUDPListener    *socks.UDPListener
	httpListener        *http.Listener
	redirListener       *redir.Listener
	redirUDPListener    *tproxy.UDPListener
	tproxyListener      *tproxy.Listener
	tproxyUDPListener   *tproxy.UDPListener
	mixedListener       *mixed.Listener
	mixedUDPLister      *socks.UDPListener
	mixECListener       *mixec.Listener
	shadowSocksListener *shadowsocks.Listener
	tcpTunListener      *tunnel.Listener
	udpTunListener      *tunnel.UdpListener
	mtpListener         *mtproxy.Listener

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
	mtpMux    sync.Mutex
)

type Ports struct {
	Port              int    `json:"port"`
	SocksPort         int    `json:"socks-port"`
	RedirPort         int    `json:"redir-port"`
	MixedPort         int    `json:"mixed-port"`
	TProxyPort        int    `json:"tproxy-port"`
	MixECConfig       string `json:"mixec-config"`
	ShadowSocksConfig string `json:"ss-config"`
	TcpTunConfig      string `json:"tcptun-config"`
	UdpTunConfig      string `json:"udptun-config"`
	MTProxyConfig     string `json:"mtproxy-config"`
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

func ReCreateHTTP(port int, tcpIn chan<- C.ConnContext) error {
	httpMux.Lock()
	defer httpMux.Unlock()

	addr := genAddr(bindAddress, port, allowLan)

	if httpListener != nil {
		if httpListener.RawAddress() == addr {
			return nil
		}
		httpListener.Close()
		httpListener = nil
	}

	if portIsZero(addr) {
		return nil
	}

	var err error
	httpListener, err = http.New(addr, tcpIn)
	if err != nil {
		return err
	}

	log.Infoln("HTTP proxy listening at: %s", httpListener.Address())
	return nil
}

func ReCreateSocks(port int, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) error {
	socksMux.Lock()
	defer socksMux.Unlock()

	addr := genAddr(bindAddress, port, allowLan)

	shouldTCPIgnore := false
	shouldUDPIgnore := false

	if socksListener != nil {
		if socksListener.RawAddress() != addr {
			socksListener.Close()
			socksListener = nil
		} else {
			shouldTCPIgnore = true
		}
	}

	if socksUDPListener != nil {
		if socksUDPListener.RawAddress() != addr {
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

	tcpListener, err := socks.New(addr, tcpIn)
	if err != nil {
		return err
	}

	udpListener, err := socks.NewUDP(addr, udpIn)
	if err != nil {
		tcpListener.Close()
		return err
	}

	socksListener = tcpListener
	socksUDPListener = udpListener

	log.Infoln("SOCKS proxy listening at: %s", socksListener.Address())
	return nil
}

func ReCreateShadowSocks(shadowSocksConfig string, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) error {
	ssMux.Lock()
	defer ssMux.Unlock()

	shouldIgnore := false

	if shadowSocksListener != nil {
		if shadowSocksListener.Config() != shadowSocksConfig {
			shadowSocksListener.Close()
			shadowSocksListener = nil
		} else {
			shouldIgnore = true
		}
	}

	if shouldIgnore {
		return nil
	}

	if len(shadowSocksConfig) == 0 {
		return nil
	}

	listener, err := shadowsocks.New(shadowSocksConfig, tcpIn, udpIn)
	if err != nil {
		return err
	}

	shadowSocksListener = listener

	return nil
}

func ReCreateRedir(port int, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) error {
	redirMux.Lock()
	defer redirMux.Unlock()

	addr := genAddr(bindAddress, port, allowLan)

	if redirListener != nil {
		if redirListener.RawAddress() == addr {
			return nil
		}
		redirListener.Close()
		redirListener = nil
	}

	if redirUDPListener != nil {
		if redirUDPListener.RawAddress() == addr {
			return nil
		}
		redirUDPListener.Close()
		redirUDPListener = nil
	}

	if portIsZero(addr) {
		return nil
	}

	var err error
	redirListener, err = redir.New(addr, tcpIn)
	if err != nil {
		return err
	}

	redirUDPListener, err = tproxy.NewUDP(addr, udpIn)
	if err != nil {
		log.Warnln("Failed to start Redir UDP Listener: %s", err)
	}

	log.Infoln("Redirect proxy listening at: %s", redirListener.Address())
	return nil
}

func ReCreateTcpTun(config string, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) error {
	tcpTunMux.Lock()
	defer tcpTunMux.Unlock()
	shouldIgnore := false

	if tcpTunListener != nil {
		if tcpTunListener.Config() != config {
			tcpTunListener.Close()
			tcpTunListener = nil
		} else {
			shouldIgnore = true
		}
	}

	if shouldIgnore {
		return nil
	}

	tcpListener, err := tunnel.New(config, tcpIn)
	if err != nil {
		return err
	}

	tcpTunListener = tcpListener

	return nil
}

func ReCreateUdpTun(config string, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) error {
	udpTunMux.Lock()
	defer udpTunMux.Unlock()
	shouldIgnore := false

	if udpTunListener != nil {
		if udpTunListener.Config() != config {
			udpTunListener.Close()
			udpTunListener = nil
		} else {
			shouldIgnore = true
		}
	}

	if shouldIgnore {
		return nil
	}

	udpListener, err := tunnel.NewUdp(config, udpIn)
	if err != nil {
		return err
	}

	udpTunListener = udpListener

	return nil
}

func ReCreateTProxy(port int, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) error {
	tproxyMux.Lock()
	defer tproxyMux.Unlock()

	addr := genAddr(bindAddress, port, allowLan)

	if tproxyListener != nil {
		if tproxyListener.RawAddress() == addr {
			return nil
		}
		tproxyListener.Close()
		tproxyListener = nil
	}

	if tproxyUDPListener != nil {
		if tproxyUDPListener.RawAddress() == addr {
			return nil
		}
		tproxyUDPListener.Close()
		tproxyUDPListener = nil
	}

	if portIsZero(addr) {
		return nil
	}

	var err error
	tproxyListener, err = tproxy.New(addr, tcpIn)
	if err != nil {
		return err
	}

	tproxyUDPListener, err = tproxy.NewUDP(addr, udpIn)
	if err != nil {
		log.Warnln("Failed to start TProxy UDP Listener: %s", err)
	}

	log.Infoln("TProxy server listening at: %s", tproxyListener.Address())
	return nil
}

func ReCreateMixed(port int, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) error {
	mixedMux.Lock()
	defer mixedMux.Unlock()

	addr := genAddr(bindAddress, port, allowLan)

	shouldTCPIgnore := false
	shouldUDPIgnore := false

	if mixedListener != nil {
		if mixedListener.RawAddress() != addr {
			mixedListener.Close()
			mixedListener = nil
		} else {
			shouldTCPIgnore = true
		}
	}
	if mixedUDPLister != nil {
		if mixedUDPLister.RawAddress() != addr {
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
	mixedListener, err = mixed.New(addr, tcpIn)
	if err != nil {
		return err
	}

	mixedUDPLister, err = socks.NewUDP(addr, udpIn)
	if err != nil {
		mixedListener.Close()
		return err
	}

	log.Infoln("Mixed(http+socks) proxy listening at: %s", mixedListener.Address())
	return nil
}

func ReCreateMixEC(config string, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) error {
	mixECMux.Lock()
	defer mixECMux.Unlock()

	shouldIgnore := false

	if mixECListener != nil {
		if mixECListener.Config() != config {
			mixECListener.Close()
			mixECListener = nil
		} else {
			shouldIgnore = true
		}
	}

	if shouldIgnore {
		return nil
	}

	var err error
	listener, err := mixec.New(config, tcpIn, udpIn)
	if err != nil {
		return err
	}
	mixECListener = listener

	return nil
}

func ReCreateMTProxy(config string, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) error {
	mtpMux.Lock()
	defer mtpMux.Unlock()

	shouldIgnore := false

	if mtpListener != nil {
		if mtpListener.Config() != config {
			mtpListener.Close()
			mtpListener = nil
		} else {
			shouldIgnore = true
		}
	}

	if shouldIgnore {
		return nil
	}

	mtp, err := mtproxy.New(config, tcpIn)
	if err != nil {
		return err
	}

	mtpListener = mtp

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

	if mixECListener != nil {
		ports.MixECConfig = mixECListener.Config()
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
		}
		return fmt.Sprintf("%s:%d", host, port)
	}

	return fmt.Sprintf("127.0.0.1:%d", port)
}
