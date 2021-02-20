package route

import (
	"net/http"
	"path/filepath"

	"github.com/Dreamacro/clash/adapters/provider"
	"github.com/Dreamacro/clash/config"
	"github.com/Dreamacro/clash/hub/executor"
	"github.com/Dreamacro/clash/log"
	P "github.com/Dreamacro/clash/proxy"
	"github.com/Dreamacro/clash/tunnel"

	"github.com/go-chi/chi"
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
	Tun                    *config.Tun        `json:"tun"`
	ShadowSocksConfig      *string            `json:"ss-config"`
	TcptunConfig           *string            `json:"tcptun-config"`
	UdptunConfig           *string            `json:"udptun-config"`
	AllowLan               *bool              `json:"allow-lan"`
	BindAddress            *string            `json:"bind-address"`
	Mode                   *tunnel.TunnelMode `json:"mode"`
	LogLevel               *log.LogLevel      `json:"log-level"`
	HealthCheckLazyDefault *bool              `json:"health-check-lazy-default"`
	TouchAfterLazyPassNum  *int               `json:"touch-after-lazy-pass-num"`
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

func pointerOrDefault_string(p *string, def string) string {
	if p != nil {
		return *p
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
	_ = P.ReCreateHTTP(pointerOrDefault(general.Port, ports.Port))
	_ = P.ReCreateSocks(pointerOrDefault(general.SocksPort, ports.SocksPort))
	_ = P.ReCreateRedir(pointerOrDefault(general.RedirPort, ports.RedirPort))
	_ = P.ReCreateTProxy(pointerOrDefault(general.TProxyPort, ports.TProxyPort))
	_ = P.ReCreateMixed(pointerOrDefault(general.MixedPort, ports.MixedPort))
	_ = P.ReCreateShadowSocks(pointerOrDefault_string(general.ShadowSocksConfig, ports.ShadowSocksConfig))
	_ = P.ReCreateTcpTun(pointerOrDefault_string(general.TcptunConfig, ports.TcpTunConfig))
	_ = P.ReCreateUdpTun(pointerOrDefault_string(general.UdptunConfig, ports.UdpTunConfig))

	if general.Tun != nil {
		if err := P.ReCreateTun(*general.Tun); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
	}

	if general.Tun != nil {
		if err := P.ReCreateTun(*general.Tun); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
	}

	if general.Mode != nil {
		tunnel.SetMode(*general.Mode)
	}

	if general.LogLevel != nil {
		log.SetLevel(*general.LogLevel)
	}

	if general.HealthCheckLazyDefault != nil {
		provider.SetHealthCheckLazyDefault(*general.HealthCheckLazyDefault)
	}

	if general.TouchAfterLazyPassNum != nil {
		provider.SetTouchAfterLazyPassNum(*general.TouchAfterLazyPassNum)
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
