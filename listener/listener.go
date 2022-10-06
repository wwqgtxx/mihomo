package proxy

import (
	"fmt"
	"net"
	"runtime"
	"strconv"
	"sync"

	"github.com/Dreamacro/clash/adapter/inbound"
	"github.com/Dreamacro/clash/component/dialer"
	"github.com/Dreamacro/clash/component/iface"
	"github.com/Dreamacro/clash/config"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/listener/http"
	"github.com/Dreamacro/clash/listener/mixec"
	"github.com/Dreamacro/clash/listener/mixed"
	"github.com/Dreamacro/clash/listener/mtproxy"
	"github.com/Dreamacro/clash/listener/redir"
	"github.com/Dreamacro/clash/listener/sing_shadowsocks"
	"github.com/Dreamacro/clash/listener/sing_tun"
	"github.com/Dreamacro/clash/listener/sing_vmess"
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
	tunLister           *sing_tun.Listener
	mixECListener       *mixec.Listener
	shadowSocksListener *sing_shadowsocks.Listener
	vmessListener       *sing_vmess.Listener
	tcpTunListener      *tunnel.Listener
	udpTunListener      *tunnel.UdpListener
	mtpListener         *mtproxy.Listener

	// lock for recreate function
	socksMux  sync.Mutex
	httpMux   sync.Mutex
	redirMux  sync.Mutex
	tproxyMux sync.Mutex
	mixedMux  sync.Mutex
	tunMux    sync.Mutex
	mixECMux  sync.Mutex
	ssMux     sync.Mutex
	vmessMux  sync.Mutex
	tcpTunMux sync.Mutex
	udpTunMux sync.Mutex
	mtpMux    sync.Mutex

	tunConfig config.Tun
)

type Ports struct {
	Port              int    `json:"port"`
	SocksPort         int    `json:"socks-port"`
	RedirPort         int    `json:"redir-port"`
	MixedPort         int    `json:"mixed-port"`
	TProxyPort        int    `json:"tproxy-port"`
	MixECConfig       string `json:"mixec-config"`
	ShadowSocksConfig string `json:"ss-config"`
	VmessConfig       string `json:"vmess-config"`
	TcpTunConfig      string `json:"tcptun-config"`
	UdpTunConfig      string `json:"udptun-config"`
	MTProxyConfig     string `json:"mtproxy-config"`
}

func Tun() config.Tun {
	if tunLister == nil {
		return tunConfig
	}
	return tunLister.Config()
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

func ReCreateHTTP(port int, tcpIn chan<- C.ConnContext) {
	httpMux.Lock()
	defer httpMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start HTTP server error: %s", err.Error())
		}
	}()

	addr := genAddr(bindAddress, port, allowLan)

	if httpListener != nil {
		if httpListener.RawAddress() == addr {
			return
		}
		httpListener.Close()
		httpListener = nil
	}

	if portIsZero(addr) {
		return
	}

	httpListener, err = http.New(addr, tcpIn)
	if err != nil {
		return
	}

	log.Infoln("HTTP proxy listening at: %s", httpListener.Address())
}

func ReCreateSocks(port int, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	socksMux.Lock()
	defer socksMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start SOCKS server error: %s", err.Error())
		}
	}()

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
		return
	}

	if portIsZero(addr) {
		return
	}

	tcpListener, err := socks.New(addr, tcpIn)
	if err != nil {
		return
	}

	udpListener, err := socks.NewUDP(addr, udpIn)
	if err != nil {
		tcpListener.Close()
		return
	}

	socksListener = tcpListener
	socksUDPListener = udpListener

	log.Infoln("SOCKS proxy listening at: %s", socksListener.Address())
}

func ReCreateRedir(port int, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	redirMux.Lock()
	defer redirMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start Redir server error: %s", err.Error())
		}
	}()

	addr := genAddr(bindAddress, port, allowLan)

	if redirListener != nil {
		if redirListener.RawAddress() == addr {
			return
		}
		redirListener.Close()
		redirListener = nil
	}

	if redirUDPListener != nil {
		if redirUDPListener.RawAddress() == addr {
			return
		}
		redirUDPListener.Close()
		redirUDPListener = nil
	}

	if portIsZero(addr) {
		return
	}

	redirListener, err = redir.New(addr, tcpIn)
	if err != nil {
		return
	}

	redirUDPListener, err = tproxy.NewUDP(addr, udpIn)
	if err != nil {
		log.Warnln("Failed to start Redir UDP Listener: %s", err)
	}

	log.Infoln("Redirect proxy listening at: %s", redirListener.Address())
}

func ReCreateShadowSocks(shadowSocksConfig string, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	ssMux.Lock()
	defer ssMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start ShadowSocks server error: %s", err.Error())
		}
	}()

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
		return
	}

	if len(shadowSocksConfig) == 0 {
		return
	}

	listener, err := sing_shadowsocks.New(shadowSocksConfig, tcpIn, udpIn)
	if err != nil {
		return
	}

	shadowSocksListener = listener

	return
}

func ReCreateVmess(vmessConfig string, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	vmessMux.Lock()
	defer vmessMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start Vmess server error: %s", err.Error())
		}
	}()

	shouldIgnore := false

	if vmessListener != nil {
		if vmessListener.Config() != vmessConfig {
			vmessListener.Close()
			vmessListener = nil
		} else {
			shouldIgnore = true
		}
	}

	if shouldIgnore {
		return
	}

	if len(vmessConfig) == 0 {
		return
	}

	listener, err := sing_vmess.New(vmessConfig, tcpIn, udpIn)
	if err != nil {
		return
	}

	vmessListener = listener

	return
}

func ReCreateTcpTun(config string, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	tcpTunMux.Lock()
	defer tcpTunMux.Unlock()
	shouldIgnore := false

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start TcpTun server error: %s", err.Error())
		}
	}()

	if tcpTunListener != nil {
		if tcpTunListener.Config() != config {
			tcpTunListener.Close()
			tcpTunListener = nil
		} else {
			shouldIgnore = true
		}
	}

	if shouldIgnore {
		return
	}

	tcpListener, err := tunnel.New(config, tcpIn)
	if err != nil {
		return
	}

	tcpTunListener = tcpListener

	return
}

func ReCreateUdpTun(config string, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	udpTunMux.Lock()
	defer udpTunMux.Unlock()
	shouldIgnore := false

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start UdpTun server error: %s", err.Error())
		}
	}()

	if udpTunListener != nil {
		if udpTunListener.Config() != config {
			udpTunListener.Close()
			udpTunListener = nil
		} else {
			shouldIgnore = true
		}
	}

	if shouldIgnore {
		return
	}

	udpListener, err := tunnel.NewUdp(config, udpIn)
	if err != nil {
		return
	}

	udpTunListener = udpListener

	return
}

func ReCreateTProxy(port int, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	tproxyMux.Lock()
	defer tproxyMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start TProxy server error: %s", err.Error())
		}
	}()

	addr := genAddr(bindAddress, port, allowLan)

	if tproxyListener != nil {
		if tproxyListener.RawAddress() == addr {
			return
		}
		tproxyListener.Close()
		tproxyListener = nil
	}

	if tproxyUDPListener != nil {
		if tproxyUDPListener.RawAddress() == addr {
			return
		}
		tproxyUDPListener.Close()
		tproxyUDPListener = nil
	}

	if portIsZero(addr) {
		return
	}

	tproxyListener, err = tproxy.New(addr, tcpIn)
	if err != nil {
		return
	}

	tproxyUDPListener, err = tproxy.NewUDP(addr, udpIn)
	if err != nil {
		log.Warnln("Failed to start TProxy UDP Listener: %s", err)
	}

	log.Infoln("TProxy server listening at: %s", tproxyListener.Address())
}

func ReCreateMixed(port int, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	mixedMux.Lock()
	defer mixedMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start Mixed(http+socks) server error: %s", err.Error())
		}
	}()

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
		return
	}

	if portIsZero(addr) {
		return
	}

	mixedListener, err = mixed.New(addr, tcpIn)
	if err != nil {
		return
	}

	mixedUDPLister, err = socks.NewUDP(addr, udpIn)
	if err != nil {
		mixedListener.Close()
		return
	}

	log.Infoln("Mixed(http+socks) proxy listening at: %s", mixedListener.Address())
}

func ReCreateTun(conf config.Tun, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	tunMux.Lock()
	defer tunMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start Tun interface error: %s", err.Error())
		}
	}()

	tunConfig = conf

	if tunLister != nil {
		tunLister.Close()
		tunLister = nil
	}

	generalInterface := dialer.GeneralInterface.Load()
	defaultInterface := dialer.DefaultInterface.Load()
	if !conf.Enable {
		if defaultInterface != generalInterface {
			log.Infoln("Use interface name: %s", generalInterface)
			dialer.DefaultInterface.Store(generalInterface)
			iface.FlushCache()
		}
		return
	}

	tunLister, err = sing_tun.New(conf, tcpIn, udpIn)

	return
}

func ReCreateMixEC(config string, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	mixECMux.Lock()
	defer mixECMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start MixEC(RESTful Api and socks5) server error: %s", err.Error())
		}
	}()

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
		return
	}

	if len(config) == 0 {
		return
	}

	listener, err := mixec.New(config, tcpIn, udpIn)
	if err != nil {
		return
	}
	mixECListener = listener

	return
}

func ReCreateMTProxy(config string, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) {
	mtpMux.Lock()
	defer mtpMux.Unlock()

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start MTProxy server error: %s", err.Error())
		}
	}()

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
		return
	}

	mtp, err := mtproxy.New(config, tcpIn)
	if err != nil {
		return
	}

	mtpListener = mtp

	return
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

	if vmessListener != nil {
		ports.VmessConfig = vmessListener.Config()
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

// CleanUp clean up something
func CleanUp() {
	if runtime.GOOS == "windows" {
		if tunLister != nil {
			tunLister.Close()
			tunLister = nil
		}
	}
}
