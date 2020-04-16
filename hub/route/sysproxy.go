package route

import (
	"github.com/go-chi/chi"
	"github.com/go-chi/render"
	"github.com/wwqgtxx/clashr/hub/executor"
	"net/http"
	"os/exec"
	"strconv"
)

const (
	Gsettings = "gsettings"
	Set       = "set"

	SystemProxy      = "org.gnome.system.proxy"
	SystemProxyHttp  = "org.gnome.system.proxy.http"
	SystemProxyHttps = "org.gnome.system.proxy.https"
	SystemProxySocks = "org.gnome.system.proxy.socks"

	ProxyHost = "host"
	ProxyPort = "port"

	ProxyMode = "mode"
	None      = "none"
	Manual    = "manual"
)

func systemProxySettingRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/http", setSystemProxyHttp)
	r.Get("/socks", setSystemProxySocks)
	r.Get("/none", closeSystemProxy)
	return r
}

func setSystemProxyHttp(w http.ResponseWriter, r *http.Request) {
	config := executor.GetGeneral()
	err := exec.Command(Gsettings, Set, SystemProxyHttp, ProxyHost, config.BindAddress).Run()
	err = exec.Command(Gsettings, Set, SystemProxyHttp, ProxyPort, strconv.Itoa(config.Port)).Run()
	err = exec.Command(Gsettings, Set, SystemProxy, ProxyMode, Manual).Run()
	if err != nil {
		render.JSON(w, r, render.M{
			"success": false,
			"err":     err.Error(),
		})
	} else {
		render.JSON(w, r, render.M{
			"success": true,
		})
	}
}

func setSystemProxySocks(w http.ResponseWriter, r *http.Request) {
	config := executor.GetGeneral()
	err := exec.Command(Gsettings, Set, SystemProxySocks, ProxyHost, config.BindAddress).Run()
	err = exec.Command(Gsettings, Set, SystemProxySocks, ProxyPort, strconv.Itoa(config.SocksPort)).Run()
	err = exec.Command(Gsettings, Set, SystemProxy, ProxyMode, Manual).Run()
	if err != nil {
		render.JSON(w, r, render.M{
			"success": false,
			"err":     err.Error(),
		})
	} else {
		render.JSON(w, r, render.M{
			"success": true,
		})
	}
}

func closeSystemProxy(w http.ResponseWriter, r *http.Request) {
	err := exec.Command(Gsettings, Set, SystemProxy, ProxyMode, None).Run()
	if err != nil {
		render.JSON(w, r, render.M{
			"success": false,
			"err":     err.Error(),
		})
	} else {
		render.JSON(w, r, render.M{
			"success": true,
		})
	}
}
