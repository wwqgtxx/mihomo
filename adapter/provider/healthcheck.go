package provider

import (
	"context"
	"time"

	"github.com/Dreamacro/clash/common/batch"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"

	"github.com/gofrs/uuid"
	"go.uber.org/atomic"
)

const (
	defaultURLTestTimeout = time.Second * 5
	waitAfterAURLTest     = time.Millisecond * 100
)

var (
	healthCheckLazyDefault = true
	touchAfterLazyPassNum  = 0
)

type HealthCheckOption struct {
	URL      string
	Interval uint
}

type HealthCheck struct {
	url        string
	proxies    []C.Proxy
	interval   uint
	lazy       bool
	lastTouch  *atomic.Int64
	done       chan struct{}
	gtype      string
	checking   *atomic.Bool
	cleanerRun *atomic.Bool
}

func (hc *HealthCheck) process() {
	ticker := time.NewTicker(time.Duration(hc.interval) * time.Second)
	passNum := 0

	go hc.lazyCheck()

	for {
		select {
		case <-ticker.C:
			if hc.lazyCheck() {
				passNum = 0
			} else {
				passNum++
				if passNum > 0 && passNum > touchAfterLazyPassNum {
					hc.touch()
				}
			}
		case <-hc.done:
			ticker.Stop()
			return
		}
	}
}

func (hc *HealthCheck) lazyCheck() bool {
	now := time.Now().Unix()
	if !hc.lazy || now-hc.lastTouch.Load() < int64(hc.interval) {
		hc.check()
		return true
	} else {
		return false
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
	if hc.checking.Swap(true) {
		log.Infoln("A Health Checking is Running, break")
		return
	}
	defer func() {
		hc.checking.Store(false)
	}()
	id := ""
	if uid, err := uuid.NewV4(); err == nil {
		id = uid.String()
	}
	log.Infoln("Start New Health Checking {%s}", id)
	switch hc.gtype {
	case "fallback":
		hc.fallbackCheck(id)
	default:
		hc.normalCheck(id)
	}
	log.Infoln("Finish A Health Checking {%s}", id)
}

func (hc *HealthCheck) normalCheck(id string) {
	b, _ := batch.New(context.Background(), batch.WithConcurrencyNum(10))
	for _, proxy := range hc.proxies {
		p := proxy
		b.Go(p.Name(), func() (any, error) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultURLTestTimeout)
			defer cancel()
			log.Infoln("Health Checking %s {%s}", proxy.Name(), id)
			p.URLTest(ctx, hc.url)
			log.Infoln("Health Checked %s : %t %d ms {%s}", p.Name(), p.Alive(), p.LastDelay(), id)
			return nil, nil
		})
	}
	b.Wait()
}

func (hc *HealthCheck) fallbackCheck(id string) {
	check := func(proxy C.Proxy) {
		ctx, cancel := context.WithTimeout(context.Background(), defaultURLTestTimeout)
		defer cancel()
		log.Infoln("Health Checking %s {%s}", proxy.Name(), id)
		proxy.URLTest(ctx, hc.url)
		log.Infoln("Health Checked %s : %t %d ms {%s}", proxy.Name(), proxy.Alive(), proxy.LastDelay(), id)
	}
	wait := func() {
		<-time.After(waitAfterAURLTest)
	}
	cleaner := func() {
		if hc.cleanerRun.Swap(true) {
			log.Infoln("A Health Check Cleaner is Running, break")
			return
		}
		defer func() {
			hc.cleanerRun.Store(false)
		}()
		log.Infoln("Start New Health Check Cleaner {%s}", id)
		b, _ := batch.New(context.Background(), batch.WithConcurrencyNum(10))
		for _, proxy := range hc.proxies {
			if proxy.Alive() {
				continue
			}
			wait()
			p := proxy
			b.Go(p.Name(), func() (any, error) {
				check(p)
				return nil, nil
			})
		}
		b.Wait()
		log.Infoln("Finish A Health Check Cleaner {%s}", id)
	}
	for _, proxy := range hc.proxies {
		if proxy.Alive() {
			wait()
			check(proxy)
			if proxy.Alive() {
				break
			}
		}
	}
	go cleaner()
}

func (hc *HealthCheck) close() {
	hc.done <- struct{}{}
}

func NewHealthCheck(proxies []C.Proxy, url string, interval uint, lazy bool, gtype string) *HealthCheck {
	if url == "" {
		url = "http://cp.cloudflare.com/generate_204"
	}
	return &HealthCheck{
		proxies:    proxies,
		url:        url,
		interval:   interval,
		lazy:       lazy,
		lastTouch:  atomic.NewInt64(0),
		done:       make(chan struct{}, 1),
		gtype:      gtype,
		checking:   atomic.NewBool(false),
		cleanerRun: atomic.NewBool(false),
	}
}

func HealthCheckLazyDefault() bool {
	return healthCheckLazyDefault
}

func SetHealthCheckLazyDefault(newHealthCheckLazyDefault bool) {
	healthCheckLazyDefault = newHealthCheckLazyDefault
}

func TouchAfterLazyPassNum() int {
	return touchAfterLazyPassNum
}

func SetTouchAfterLazyPassNum(newTouchAfterLazyPassNum int) {
	touchAfterLazyPassNum = newTouchAfterLazyPassNum
}
