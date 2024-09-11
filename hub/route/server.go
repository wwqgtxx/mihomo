package route

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	CN "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/render"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

var (
	uiPath = ""

	httpServer *http.Server
	tlsServer  *http.Server
	unixServer *http.Server

	builtinMimeTypesLower = map[string]string{
		".css":  "text/css; charset=utf-8",
		".gif":  "image/gif",
		".htm":  "text/html; charset=utf-8",
		".html": "text/html; charset=utf-8",
		".jpg":  "image/jpeg",
		".js":   "application/javascript",
		".wasm": "application/wasm",
		".pdf":  "application/pdf",
		".png":  "image/png",
		".svg":  "image/svg+xml",
		".xml":  "text/xml; charset=utf-8",
	}
)

type Traffic struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

type Config struct {
	Addr        string
	TLSAddr     string
	UnixAddr    string
	Secret      string
	Certificate string
	PrivateKey  string
	DohServer   string
	IsDebug     bool
}

func ReCreateServer(cfg *Config) {
	C.SetECHandler(router(false, cfg.Secret, cfg.DohServer))
	go start(cfg)
	go startTLS(cfg)
	go startUnix(cfg)
}

func SetUIPath(path string) {
	uiPath = C.Path.Resolve(path)
}

func router(isDebug bool, secret string, dohServer string) *chi.Mux {
	r := chi.NewRouter()

	corsM := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
		AllowedHeaders: []string{"Content-Type", "Authorization"},
		MaxAge:         300,
	})
	r.Use(setPrivateNetworkAccess)
	r.Use(corsM.Handler)
	r.NotFound(closeTcpHandle)
	r.MethodNotAllowed(closeTcpHandle)
	if isDebug {
		r.Mount("/debug", func() http.Handler {
			r := chi.NewRouter()
			r.Put("/gc", func(w http.ResponseWriter, r *http.Request) {
				debug.FreeOSMemory()
			})
			handler := middleware.Profiler
			r.Mount("/", handler())
			return r
		}())
	}
	r.Group(func(r chi.Router) {
		if secret != "" {
			r.Use(authentication(secret))
		}

		//r.Get("/", hello)
		r.Get("/logs", getLogs)
		r.Get("/traffic", traffic)
		r.Get("/version", version)
		r.Mount("/configs", configRouter())
		r.Mount("/proxies", proxyRouter())
		r.Mount("/rules", ruleRouter())
		r.Mount("/connections", connectionRouter())
		r.Mount("/providers/proxies", proxyProviderRouter())
		r.Mount("/providers/rules", ruleProviderRouter())
		r.Mount("/script", scriptRouter())
		r.Mount("/dns", dnsRouter())
		r.Mount("/restart", restartRouter())
	})

	if uiPath != "" {
		r.Group(func(r chi.Router) {
			fs := http.StripPrefix("/ui", http.FileServer(http.Dir(uiPath)))
			r.Get("/ui", http.RedirectHandler("/ui/", http.StatusTemporaryRedirect).ServeHTTP)
			r.Get("/ui/*", func(w http.ResponseWriter, r *http.Request) {
				// fix for windows mime error
				// ref: https://github.com/golang/go/issues/32350
				if v, ok := builtinMimeTypesLower[filepath.Ext(r.URL.Path)]; ok {
					w.Header().Set("Content-Type", v)
				}

				// change mihomo-dashboard's default url from Host
				isRootPath := r.URL.Path == "/ui/"
				if isRootPath {
					fw := &fakeResponseWriter{w, &bytes.Buffer{}, -1}
					fs.ServeHTTP(fw, r)
					data := fw.buf.Bytes()
					old := []byte("<!--meta name=\"external-controller\" content=\"http://secret@example.com:9090\"-->")
					host := r.Host
					if !strings.Contains(host, ":") {
						host = host + ":80"
					}
					new := []byte(fmt.Sprintf("<meta name=\"external-controller\" content=\"http://%s\">", host))
					target := bytes.ReplaceAll(data, old, new)
					fw.buf.Reset()
					fw.buf.Write(target)

					if w.Header().Get("Content-Encoding") == "" && w.Header().Get("Content-Length") != "" {
						w.Header().Set("Content-Length", strconv.FormatInt(int64(len(target)), 10))
					}
					if fw.statusCode != -1 {
						w.WriteHeader(fw.statusCode)
					}
					_, _ = io.Copy(w, fw.buf)
					return
				}

				fs.ServeHTTP(w, r)
			})
		})
	}
	if len(dohServer) > 0 && dohServer[0] == '/' {
		r.Mount(dohServer, dohRouter())
	}

	return r
}

type fakeResponseWriter struct {
	http.ResponseWriter
	buf        *bytes.Buffer
	statusCode int
}

func (w *fakeResponseWriter) Write(buf []byte) (int, error) {
	w.buf.Write(buf)
	return len(buf), nil
}

func (w *fakeResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}

func start(cfg *Config) {
	// first stop existing server
	if httpServer != nil {
		_ = httpServer.Close()
		httpServer = nil
	}

	// handle addr
	if len(cfg.Addr) > 0 {
		l, err := inbound.Listen("tcp", cfg.Addr)
		if err != nil {
			log.Errorln("External controller listen error: %s", err)
			return
		}
		log.Infoln("RESTful API listening at: %s", l.Addr().String())

		server := &http.Server{
			Handler: router(cfg.IsDebug, cfg.Secret, cfg.DohServer),
		}
		httpServer = server
		if err = server.Serve(l); err != nil {
			log.Errorln("External controller serve error: %s", err)
		}
	}
}

func startTLS(cfg *Config) {
	// first stop existing server
	if tlsServer != nil {
		_ = tlsServer.Close()
		tlsServer = nil
	}

	// handle tlsAddr
	if len(cfg.TLSAddr) > 0 {
		c, err := CN.ParseCert(cfg.Certificate, cfg.PrivateKey, C.Path)
		if err != nil {
			log.Errorln("External controller tls listen error: %s", err)
			return
		}

		l, err := inbound.Listen("tcp", cfg.TLSAddr)
		if err != nil {
			log.Errorln("External controller tls listen error: %s", err)
			return
		}

		log.Infoln("RESTful API tls listening at: %s", l.Addr().String())
		server := &http.Server{
			Handler: router(cfg.IsDebug, cfg.Secret, cfg.DohServer),
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{c},
			},
		}
		tlsServer = server
		if err = server.ServeTLS(l, "", ""); err != nil {
			log.Errorln("External controller tls serve error: %s", err)
		}
	}
}

func startUnix(cfg *Config) {
	// first stop existing server
	if unixServer != nil {
		_ = unixServer.Close()
		unixServer = nil
	}

	// handle addr
	if len(cfg.UnixAddr) > 0 {
		addr := C.Path.Resolve(cfg.UnixAddr)

		dir := filepath.Dir(addr)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				log.Errorln("External controller unix listen error: %s", err)
				return
			}
		}

		// https://devblogs.microsoft.com/commandline/af_unix-comes-to-windows/
		//
		// Note: As mentioned above in the ‘security’ section, when a socket binds a socket to a valid pathname address,
		// a socket file is created within the filesystem. On Linux, the application is expected to unlink
		// (see the notes section in the man page for AF_UNIX) before any other socket can be bound to the same address.
		// The same applies to Windows unix sockets, except that, DeleteFile (or any other file delete API)
		// should be used to delete the socket file prior to calling bind with the same path.
		_ = syscall.Unlink(addr)

		l, err := inbound.Listen("unix", addr)
		if err != nil {
			log.Errorln("External controller unix listen error: %s", err)
			return
		}
		log.Infoln("RESTful API unix listening at: %s", l.Addr().String())

		server := &http.Server{
			Handler: router(cfg.IsDebug, "", cfg.DohServer),
		}
		unixServer = server
		if err = server.Serve(l); err != nil {
			log.Errorln("External controller unix serve error: %s", err)
		}
	}

}

func setPrivateNetworkAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			w.Header().Add("Access-Control-Allow-Private-Network", "true")
		}
		next.ServeHTTP(w, r)
	})
}

func safeEqual(a, b string) bool {
	aBuf := utils.ImmutableBytesFromString(a)
	bBuf := utils.ImmutableBytesFromString(b)
	return subtle.ConstantTimeCompare(aBuf, bBuf) == 1
}

func authentication(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			// Browser websocket not support custom header
			if r.Header.Get("Upgrade") == "websocket" && r.URL.Query().Get("token") != "" {
				token := r.URL.Query().Get("token")
				if !safeEqual(token, secret) {
					render.Status(r, http.StatusUnauthorized)
					render.JSON(w, r, ErrUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			header := r.Header.Get("Authorization")
			bearer, token, found := strings.Cut(header, " ")

			hasInvalidHeader := bearer != "Bearer"
			hasInvalidSecret := !found || !safeEqual(token, secret)
			if hasInvalidHeader || hasInvalidSecret {
				render.Status(r, http.StatusUnauthorized)
				render.JSON(w, r, ErrUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

func hello(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{"hello": "mihomo"})
}

func traffic(w http.ResponseWriter, r *http.Request) {
	var wsConn net.Conn
	if r.Header.Get("Upgrade") == "websocket" {
		var err error
		wsConn, _, _, err = ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
	}

	if wsConn == nil {
		w.Header().Set("Content-Type", "application/json")
		render.Status(r, http.StatusOK)
	}

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	t := statistic.DefaultManager
	buf := &bytes.Buffer{}
	var err error
	for range tick.C {
		buf.Reset()
		up, down := t.Now()
		if err := json.NewEncoder(buf).Encode(Traffic{
			Up:   up,
			Down: down,
		}); err != nil {
			break
		}

		if wsConn == nil {
			_, err = w.Write(buf.Bytes())
			w.(http.Flusher).Flush()
		} else {
			err = wsutil.WriteMessage(wsConn, ws.StateServerSide, ws.OpText, buf.Bytes())
		}

		if err != nil {
			break
		}
	}
}

type Log struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
}
type LogStructuredField struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
type LogStructured struct {
	Time    string               `json:"time"`
	Level   string               `json:"level"`
	Message string               `json:"message"`
	Fields  []LogStructuredField `json:"fields"`
}

func getLogs(w http.ResponseWriter, r *http.Request) {
	levelText := r.URL.Query().Get("level")
	if levelText == "" {
		levelText = "info"
	}

	formatText := r.URL.Query().Get("format")
	isStructured := false
	if formatText == "structured" {
		isStructured = true
	}

	level, ok := log.LogLevelMapping[levelText]
	if !ok {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	var wsConn net.Conn
	if r.Header.Get("Upgrade") == "websocket" {
		var err error
		wsConn, _, _, err = ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
	}

	if wsConn == nil {
		w.Header().Set("Content-Type", "application/json")
		render.Status(r, http.StatusOK)
	}

	ch := make(chan log.Event, 1024)
	sub := log.Subscribe()
	defer log.UnSubscribe(sub)
	buf := &bytes.Buffer{}

	go func() {
		for elm := range sub {
			log := elm.(log.Event)
			select {
			case ch <- log:
			default:
			}
		}
		close(ch)
	}()

	for logM := range ch {
		if logM.LogLevel < level {
			continue
		}
		buf.Reset()

		if !isStructured {
			if err := json.NewEncoder(buf).Encode(Log{
				Type:    logM.Type(),
				Payload: logM.Payload,
			}); err != nil {
				break
			}
		} else {
			newLevel := logM.Type()
			if newLevel == "warning" {
				newLevel = "warn"
			}
			if err := json.NewEncoder(buf).Encode(LogStructured{
				Time:    time.Now().Format(time.TimeOnly),
				Level:   newLevel,
				Message: logM.Payload,
				Fields:  []LogStructuredField{},
			}); err != nil {
				break
			}
		}

		var err error
		if wsConn == nil {
			_, err = w.Write(buf.Bytes())
			w.(http.Flusher).Flush()
		} else {
			err = wsutil.WriteMessage(wsConn, ws.StateServerSide, ws.OpText, buf.Bytes())
		}

		if err != nil {
			break
		}
	}
}

func version(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{"version": C.Version, "premium": true})
}

func closeTcpHandle(writer http.ResponseWriter, request *http.Request) {
	h, ok := writer.(http.Hijacker)
	if !ok {
		return
	}
	netConn, _, err := h.Hijack()
	if err != nil {
		return
	}
	_ = netConn.Close()
}
