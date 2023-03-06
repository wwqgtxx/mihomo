package provider

import (
	"context"
	"time"

	"github.com/Dreamacro/clash/common/batch"
	"github.com/Dreamacro/clash/common/utils"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"

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
	gType      string
	gName      string
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
		log.Debugln("Skip once health check because we are lazy (%s)", hc.gName)
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
		log.Infoln("A Health Checking (%s) is Running, break", hc.gName)
		return
	}
	defer func() {
		hc.checking.Store(false)
	}()
	id := ""
	if uid, err := utils.UnsafeUUIDGenerator.NewV4(); err == nil {
		id = uid.String()
	}
	log.Infoln("Start New Health Checking (%s) {%s}", hc.gName, id)
	switch hc.gType {
	case "fallback":
		hc.fallbackCheck(id)
	default:
		hc.normalCheck(id)
	}
	log.Infoln("Finish A Health Checking (%s) {%s}", hc.gName, id)
}

func (hc *HealthCheck) normalCheck(id string) {
	b, _ := batch.New(context.Background(), batch.WithConcurrencyNum(10))
	for _, proxy := range hc.proxies {
		p := proxy
		b.Go(p.Name(), func() (any, error) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultURLTestTimeout)
			defer cancel()
			log.Infoln("Health Checking (%s) %s {%s}", hc.gName, p.Name(), id)
			p.URLTest(ctx, hc.url)
			log.Infoln("Health Checked (%s) %s : %t %d ms {%s}", hc.gName, p.Name(), p.Alive(), p.LastDelay(), id)
			return nil, nil
		})
	}
	b.Wait()
}

func (hc *HealthCheck) fallbackCheck(id string) {
	check := func(proxy C.Proxy) {
		ctx, cancel := context.WithTimeout(context.Background(), defaultURLTestTimeout)
		defer cancel()
		log.Infoln("Health Checking (%s) %s {%s}", hc.gName, proxy.Name(), id)
		proxy.URLTest(ctx, hc.url)
		log.Infoln("Health Checked (%s) %s : %t %d ms {%s}", hc.gName, proxy.Name(), proxy.Alive(), proxy.LastDelay(), id)
	}
	wait := func() {
		<-time.After(waitAfterAURLTest)
	}
	cleaner := func() {
		if hc.cleanerRun.Swap(true) {
			log.Infoln("A Health Check Cleaner (%s) is Running, break", hc.gName)
			return
		}
		defer func() {
			hc.cleanerRun.Store(false)
		}()
		log.Infoln("Start New Health Check Cleaner (%s) {%s}", hc.gName, id)
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
		log.Infoln("Finish A Health Check Cleaner (%s) {%s}", hc.gName, id)
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

func NewHealthCheck(proxies []C.Proxy, url string, interval uint, lazy bool, gType string, gName string) *HealthCheck {
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
		gType:      gType,
		gName:      gName,
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
