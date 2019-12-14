package provider

import (
	"context"
	"time"
	"sync"

	C "github.com/whojave/clash/constant"
	"github.com/whojave/clash/log"
)

const (
	defaultURLTestTimeout = time.Second * 5
	waitAfterAURLTest =  time.Second * 1
)

type HealthCheckOption struct {
	URL      string
	Interval uint
	GType string
}

type healthCheck struct {
	url     string
	proxies []C.Proxy
	ticker  *time.Ticker
	gtype string
	mutex    sync.Mutex
	checking bool
}

func (hc *healthCheck) process() {
	switch hc.gtype {
		case "fallback":
			go hc.fallbackCheck()
			for range hc.ticker.C {
				go hc.fallbackCheck()
			}
		default:
			go hc.check()
			for range hc.ticker.C {
				hc.check()
			}
	}
}

func (hc *healthCheck) check() {
	ctx, cancel := context.WithTimeout(context.Background(), defaultURLTestTimeout)
	for _, proxy := range hc.proxies {
		go proxy.URLTest(ctx, hc.url)
	}

	<-ctx.Done()
	cancel()
}

func (hc *healthCheck) fallbackCheck() {
	hc.mutex.Lock()
	if hc.checking{
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
	} ()
	log.Infoln("Start New Health Checking")
	for _, proxy := range hc.proxies {
		ctx, cancel := context.WithTimeout(context.Background(), defaultURLTestTimeout)
		log.Infoln("Health Checking %s", proxy.Name())
		proxy.URLTest(ctx, hc.url)
		//<-ctx.Done()
		cancel()
		log.Infoln("Health Checked %s : %t %d ms", proxy.Name(), proxy.Alive(), proxy.LastDelay())
		if proxy.Alive() {
			break;
		}
		<-time.After(waitAfterAURLTest)
	}

	log.Infoln("Finish A Health Checking")
}

func (hc *healthCheck) close() {
	hc.ticker.Stop()
}

func newHealthCheck(proxies []C.Proxy, url string, interval uint, gtype string) *healthCheck {
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	return &healthCheck{
		proxies: proxies,
		url:     url,
		ticker:  ticker,
		gtype:   gtype,
		checking:false,
	}
}
