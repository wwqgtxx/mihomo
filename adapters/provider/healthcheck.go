package provider

import (
	"context"
	"sync"
	"time"

	C "github.com/wwqgtxx/clashr/constant"
	"github.com/wwqgtxx/clashr/log"
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
	url      string
	proxies  []C.Proxy
	interval uint
	done     chan struct{}
	gtype    string
	mutex    sync.Mutex
	checking bool
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
			switch hc.gtype {
			case "fallback":
				go hc.fallbackCheck()
			default:
				hc.check()
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

func (hc *HealthCheck) check() {
	ctx, cancel := context.WithTimeout(context.Background(), defaultURLTestTimeout)
	for _, proxy := range hc.proxies {
		go proxy.URLTest(ctx, hc.url)
	}

	<-ctx.Done()
	cancel()
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
	log.Infoln("Start New Health Checking")
	for _, proxy := range hc.proxies {
		ctx, cancel := context.WithTimeout(context.Background(), defaultURLTestTimeout)
		log.Infoln("Health Checking %s", proxy.Name())
		proxy.URLTest(ctx, hc.url)
		//<-ctx.Done()
		cancel()
		log.Infoln("Health Checked %s : %t %d ms", proxy.Name(), proxy.Alive(), proxy.LastDelay())
		if proxy.Alive() {
			break
		}
		<-time.After(waitAfterAURLTest)
	}

	log.Infoln("Finish A Health Checking")
}

func (hc *HealthCheck) close() {
	hc.done <- struct{}{}
}

func NewHealthCheck(proxies []C.Proxy, url string, interval uint, gtype string) *HealthCheck {
	return &HealthCheck{
		proxies:  proxies,
		url:      url,
		interval: interval,
		done:     make(chan struct{}, 1),
		gtype:    gtype,
		checking: false,
	}
}
