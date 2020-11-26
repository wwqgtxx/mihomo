package provider

import (
	"context"
	"github.com/gofrs/uuid"
	"sync"
	"time"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"go.uber.org/atomic"
)

const (
	defaultURLTestTimeout = time.Second * 5
	waitAfterAURLTest     = time.Second * 1
)

type HealthCheckOption struct {
	URL      string
	Interval uint
}

type HealthCheck struct {
	url       string
	proxies   []C.Proxy
	interval  uint
	lazy      bool
	lastTouch *atomic.Int64
	done      chan struct{}
	gtype     string
	mutex     sync.Mutex
	checking  bool
}

func (hc *HealthCheck) process() {
	ticker := time.NewTicker(time.Duration(hc.interval) * time.Second)

	switch hc.gtype {
	case "fallback":
		go hc.fallbackCheck()
	default:
		go hc.check()
	}

	for {
		select {
		case <-ticker.C:
			now := time.Now().Unix()
			if !hc.lazy || now-hc.lastTouch.Load() < int64(hc.interval) {
				switch hc.gtype {
				case "fallback":
					go hc.fallbackCheck()
				default:
					hc.check()
				}
			}
		case <-hc.done:
			ticker.Stop()
			return
		}
	}
}

func (hc *HealthCheck) setProxy(proxies []C.Proxy) {
	hc.proxies = proxies
}

func (hc *HealthCheck) auto() bool {
	return hc.interval != 0
}

func (hc *HealthCheck) touch() {
	hc.lastTouch.Store(time.Now().Unix())
}

func (hc *HealthCheck) check() {
	ctx, cancel := context.WithTimeout(context.Background(), defaultURLTestTimeout)
	wg := &sync.WaitGroup{}
	id := ""
	if uid, err := uuid.NewV4(); err == nil {
		id = uid.String()
	}
	log.Infoln("Start New Health Checking {%s}", id)
	for _, proxy := range hc.proxies {
		go func(p C.Proxy) {
			p.URLTest(ctx, hc.url)
			wg.Done()
			log.Infoln("Health Checked %s : %t %d ms {%s}", p.Name(), p.Alive(), p.LastDelay(), id)
		}(proxy)
	}

	wg.Wait()
	cancel()
	log.Infoln("Finish A Health Checking {%s}", id)
}

func (hc *HealthCheck) fallbackCheck() {
	hc.mutex.Lock()
	if hc.checking {
		hc.mutex.Unlock()
		log.Infoln("A Health Checking is Running, break")
		return
	}
	hc.checking = true
	hc.mutex.Unlock()
	defer func() {
		hc.mutex.Lock()
		hc.checking = false
		hc.mutex.Unlock()
	}()
	id := ""
	if uid, err := uuid.NewV4(); err == nil {
		id = uid.String()
	}
	log.Infoln("Start New Health Checking {%s}", id)
	for _, proxy := range hc.proxies {
		ctx, cancel := context.WithTimeout(context.Background(), defaultURLTestTimeout)
		log.Infoln("Health Checking %s {%s}", proxy.Name(), id)
		proxy.URLTest(ctx, hc.url)
		//<-ctx.Done()
		cancel()
		log.Infoln("Health Checked %s : %t %d ms {%s}", proxy.Name(), proxy.Alive(), proxy.LastDelay(), id)
		if proxy.Alive() {
			break
		}
		<-time.After(waitAfterAURLTest)
	}

	log.Infoln("Finish A Health Checking {%s}", id)
}

func (hc *HealthCheck) close() {
	hc.done <- struct{}{}
}

func NewHealthCheck(proxies []C.Proxy, url string, interval uint, lazy bool, gtype string) *HealthCheck {
	return &HealthCheck{
		proxies:   proxies,
		url:       url,
		interval:  interval,
		lazy:      lazy,
		lastTouch: atomic.NewInt64(0),
		done:      make(chan struct{}, 1),
		gtype:     gtype,
		checking:  false,
	}
}
