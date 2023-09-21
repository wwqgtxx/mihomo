package dns

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/samber/lo"
	"net"
	"net/netip"
	"time"

	"github.com/Dreamacro/clash/common/cache"
	"github.com/Dreamacro/clash/common/picker"
	"github.com/Dreamacro/clash/log"

	D "github.com/miekg/dns"
)

func minimalTTL(records []D.RR) uint32 {
	minObj := lo.MinBy(records, func(r1 D.RR, r2 D.RR) bool {
		return r1.Header().Ttl < r2.Header().Ttl
	})
	if minObj != nil {
		return minObj.Header().Ttl
	}
	return 0
}

func updateTTL(records []D.RR, ttl uint32) {
	if len(records) == 0 {
		return
	}
	delta := minimalTTL(records) - ttl
	for i := range records {
		records[i].Header().Ttl = lo.Clamp(records[i].Header().Ttl-delta, 1, records[i].Header().Ttl)
	}
}

func putMsgToCache(c *cache.LruCache[string, *D.Msg], key string, msg *D.Msg) {
	putMsgToCacheWithExpire(c, key, msg, 0)
}

func putMsgToCacheWithExpire(c *cache.LruCache[string, *D.Msg], key string, msg *D.Msg, sec uint32) {
	if sec == 0 {
		if sec = minimalTTL(msg.Answer); sec == 0 {
			if sec = minimalTTL(msg.Ns); sec == 0 {
				sec = minimalTTL(msg.Extra)
			}
		}
		if sec == 0 {
			return
		}

		if sec > 120 {
			sec = 120 // at least 2 minutes to cache
		}

	}

	c.SetWithExpire(key, msg.Copy(), time.Now().Add(time.Duration(sec)*time.Second))
}

func setMsgTTL(msg *D.Msg, ttl uint32) {
	for _, answer := range msg.Answer {
		answer.Header().Ttl = ttl
	}

	for _, ns := range msg.Ns {
		ns.Header().Ttl = ttl
	}

	for _, extra := range msg.Extra {
		extra.Header().Ttl = ttl
	}
}

func updateMsgTTL(msg *D.Msg, ttl uint32) {
	updateTTL(msg.Answer, ttl)
	updateTTL(msg.Ns, ttl)
	updateTTL(msg.Extra, ttl)
}

func isIPRequest(q D.Question) bool {
	return q.Qclass == D.ClassINET && (q.Qtype == D.TypeA || q.Qtype == D.TypeAAAA || q.Qtype == D.TypeCNAME)
}

func transform(servers []NameServer, resolver *Resolver) []dnsClient {
	ret := []dnsClient{}
	for _, s := range servers {
		switch s.Net {
		case "https":
			ret = append(ret, newDoHClient(s.Addr, s.Interface, resolver, s.UseRemote, s.ProxyAdapter, s.ProxyName))
			continue
		case "dhcp":
			ret = append(ret, newDHCPClient(s.Addr))
			continue
		case "system":
			clients, err := loadSystemResolver()
			if err != nil {
				log.Errorln("[DNS:system] load system resolver failed: %s", err.Error())
				continue
			}
			if len(clients) == 0 {
				log.Errorln("[DNS:system] no nameserver found in system")
				continue
			}
			ret = append(ret, clients...)
			continue
		}

		host, port, _ := net.SplitHostPort(s.Addr)
		ret = append(ret, &client{
			Client: &D.Client{
				Net: s.Net,
				TLSConfig: &tls.Config{
					ServerName: host,
				},
				UDPSize: 4096,
				Timeout: 5 * time.Second,
			},
			port:         port,
			host:         host,
			iface:        s.Interface,
			r:            resolver,
			useRemote:    s.UseRemote,
			proxyAdapter: s.ProxyAdapter,
			proxyName:    s.ProxyName,
		})
	}
	return ret
}

func handleMsgWithEmptyAnswer(r *D.Msg) *D.Msg {
	msg := &D.Msg{}
	msg.Answer = []D.RR{}

	msg.SetRcode(r, D.RcodeSuccess)
	msg.Authoritative = true
	msg.RecursionAvailable = true

	return msg
}

func msgToIP(msg *D.Msg) []netip.Addr {
	ips := []netip.Addr{}

	for _, answer := range msg.Answer {
		switch ans := answer.(type) {
		case *D.AAAA:
			if ip, ok := netip.AddrFromSlice(ans.AAAA); ok {
				ips = append(ips, ip)
			}
		case *D.A:
			if ip, ok := netip.AddrFromSlice(ans.A); ok {
				ips = append(ips, ip)
			}
		}
	}

	return ips
}

func batchExchange(ctx context.Context, clients []dnsClient, m *D.Msg) (msg *D.Msg, err error) {
	fast, ctx := picker.WithContext(ctx)
	for _, client := range clients {
		r := client
		fast.Go(func() (any, error) {
			m, err := r.ExchangeContext(ctx, m)
			if err != nil {
				return nil, err
			} else if m.Rcode == D.RcodeServerFailure || m.Rcode == D.RcodeRefused {
				return nil, errors.New("server failure")
			}
			return m, nil
		})
	}

	elm := fast.Wait()
	if elm == nil {
		err := errors.New("all DNS requests failed")
		if fErr := fast.Error(); fErr != nil {
			err = fmt.Errorf("%w, first error: %w", err, fErr)
		}
		return nil, err
	}

	msg = elm.(*D.Msg)
	return
}
