package route

import (
	"net/http"
	"path/filepath"

	"github.com/Dreamacro/clash/adapter/provider"
	"github.com/Dreamacro/clash/component/resolver"
	"github.com/Dreamacro/clash/config"
	"github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/dns"
	"github.com/Dreamacro/clash/hub/executor"
	P "github.com/Dreamacro/clash/listener"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/tunnel"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func configRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getConfigs)
	r.Put("/", updateConfigs)
	r.Patch("/", patchConfigs)
	return r
}

type configSchema struct {
	Port                   *int               `json:"port"`
	SocksPort              *int               `json:"socks-port"`
	RedirPort              *int               `json:"redir-port"`
	TProxyPort             *int               `json:"tproxy-port"`
	MixedPort              *int               `json:"mixed-port"`
	Tun                    *tunSchema         `json:"tun"`
	MixECConfig            *string            `json:"mixec-config"`
	ShadowSocksConfig      *string            `json:"ss-config"`
	TcptunConfig           *string            `json:"tcptun-config"`
	UdptunConfig           *string            `json:"udptun-config"`
	AllowLan               *bool              `json:"allow-lan"`
	BindAddress            *string            `json:"bind-address"`
	Mode                   *tunnel.TunnelMode `json:"mode"`
	LogLevel               *log.LogLevel      `json:"log-level"`
	IPv6                   *bool              `json:"ipv6"`
	UseRemoteDnsDefault    *bool              `json:"use-remote-dns-default"`
	UseSystemDnsDial       *bool              `json:"use-system-dns-dial"`
	HealthCheckLazyDefault *bool              `json:"health-check-lazy-default"`
	TouchAfterLazyPassNum  *int               `json:"touch-after-lazy-pass-num"`
	PreResolveProcessName  *bool              `json:"pre-resolve-process-name"`
}

type tunSchema struct {
	Enable              bool      `yaml:"enable" json:"enable"`
	Stack               *string   `yaml:"stack" json:"stack"`
	DnsHijack           *[]string `yaml:"dns-hijack" json:"dns-hijack"`
	AutoRoute           *bool     `yaml:"auto-route" json:"auto-route"`
	AutoDetectInterface *bool     `yaml:"auto-detect-interface" json:"auto-detect-interface"`
}

func getConfigs(w http.ResponseWriter, r *http.Request) {
	general := executor.GetGeneral()
	render.JSON(w, r, general)
}

func pointerOrDefault(p *int, def int) int {
	if p != nil {
		return *p
	}

	return def
}

func pointerOrDefaultString(p *string, def string) string {
	if p != nil {
		return *p
	}

	return def
}

func pointerOrDefaultTun(p *tunSchema, def config.Tun) config.Tun {
	if p != nil {
		def.Enable = p.Enable
		if p.Stack != nil {
			def.Stack = *p.Stack
		}
		if p.DnsHijack != nil {
			def.DnsHijack = *p.DnsHijack
		}
		if p.AutoRoute != nil {
			def.AutoRoute = *p.AutoRoute
		}
		if p.AutoDetectInterface != nil {
			def.AutoDetectInterface = *p.AutoDetectInterface
		}
	}
	return def
}

func patchConfigs(w http.ResponseWriter, r *http.Request) {
	general := &configSchema{}
	if err := render.DecodeJSON(r.Body, general); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	if general.AllowLan != nil {
		P.SetAllowLan(*general.AllowLan)
	}

	if general.BindAddress != nil {
		P.SetBindAddress(*general.BindAddress)
	}

	ports := P.GetPorts()

	tcpIn := tunnel.TCPIn()
	udpIn := tunnel.UDPIn()

	_ = P.ReCreateHTTP(pointerOrDefault(general.Port, ports.Port), tcpIn)
	_ = P.ReCreateSocks(pointerOrDefault(general.SocksPort, ports.SocksPort), tcpIn, udpIn)
	_ = P.ReCreateRedir(pointerOrDefault(general.RedirPort, ports.RedirPort), tcpIn, udpIn)
	_ = P.ReCreateTProxy(pointerOrDefault(general.TProxyPort, ports.TProxyPort), tcpIn, udpIn)
	_ = P.ReCreateMixed(pointerOrDefault(general.MixedPort, ports.MixedPort), tcpIn, udpIn)
	_ = P.ReCreateTun(pointerOrDefaultTun(general.Tun, P.Tun()), tcpIn, udpIn)
	_ = P.ReCreateMixEC(pointerOrDefaultString(general.MixECConfig, ports.MixECConfig), tcpIn, udpIn)
	_ = P.ReCreateShadowSocks(pointerOrDefaultString(general.ShadowSocksConfig, ports.ShadowSocksConfig), tcpIn, udpIn)
	_ = P.ReCreateTcpTun(pointerOrDefaultString(general.TcptunConfig, ports.TcpTunConfig), tcpIn, udpIn)
	_ = P.ReCreateUdpTun(pointerOrDefaultString(general.UdptunConfig, ports.UdpTunConfig), tcpIn, udpIn)

	if general.Mode != nil {
		tunnel.SetMode(*general.Mode)
	}

	if general.LogLevel != nil {
		log.SetLevel(*general.LogLevel)
	}

	if general.UseRemoteDnsDefault != nil {
		dns.SetUseRemoteDnsDefault(*general.UseRemoteDnsDefault)
	}

	if general.UseSystemDnsDial != nil {
		dns.SetUseSystemDnsDial(*general.UseSystemDnsDial)
	}

	if general.HealthCheckLazyDefault != nil {
		provider.SetHealthCheckLazyDefault(*general.HealthCheckLazyDefault)
	}

	if general.TouchAfterLazyPassNum != nil {
		provider.SetTouchAfterLazyPassNum(*general.TouchAfterLazyPassNum)
	}

	if general.PreResolveProcessName != nil {
		tunnel.SetPreResolveProcessName(*general.PreResolveProcessName)
	}

	if general.IPv6 != nil {
		resolver.DisableIPv6 = !*general.IPv6

	}

	render.NoContent(w, r)
}

type updateConfigRequest struct {
	Path    string `json:"path"`
	Payload string `json:"payload"`
}

func updateConfigs(w http.ResponseWriter, r *http.Request) {
	req := updateConfigRequest{}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	force := r.URL.Query().Get("force") == "true"
	var cfg *config.Config
	var err error

	if req.Payload != "" {
		cfg, err = executor.ParseWithBytes([]byte(req.Payload))
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
	} else {
		if req.Path == "" {
			req.Path = constant.Path.Config()
		}
		if !filepath.IsAbs(req.Path) {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("path is not a absolute path"))
			return
		}

		cfg, err = executor.ParseWithPath(req.Path)
		if err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
	}

	executor.ApplyConfig(cfg, force)
	render.NoContent(w, r)
}
