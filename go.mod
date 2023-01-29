module github.com/Dreamacro/clash

go 1.19

require (
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da
	github.com/go-chi/chi/v5 v5.0.8
	github.com/go-chi/cors v1.2.1
	github.com/go-chi/render v1.0.2
	github.com/gofrs/uuid v4.3.1+incompatible
	github.com/gorilla/websocket v1.5.0
	github.com/insomniacslk/dhcp v0.0.0-20221215072855-de60144f33f8
	github.com/jpillora/backoff v1.0.0
	github.com/kentik/patricia v1.2.0
	github.com/mdlayher/netlink v1.7.2-0.20221213171556-9881fafed8c7
	github.com/metacubex/quic-go v0.31.1-0.20230117135846-c981c4c16e91
	github.com/metacubex/sing-shadowsocks v0.1.0
	github.com/metacubex/sing-tun v0.1.1-0.20230129141228-645f74b2208b
	github.com/metacubex/sing-wireguard v0.0.0-20230129141512-65b25e764f8e
	github.com/miekg/dns v1.1.50
	github.com/oschwald/geoip2-golang v1.8.0
	github.com/sagernet/netlink v0.0.0-20220905062125-8043b4a9aa97
	github.com/sagernet/sing v0.1.6
	github.com/sagernet/sing-vmess v0.1.1
	github.com/sagernet/wireguard-go v0.0.0-20221116151939-c99467f53f2c
	github.com/samber/lo v1.37.0
	github.com/sirupsen/logrus v1.9.0
	github.com/stretchr/testify v1.8.1
	go.etcd.io/bbolt v1.3.6
	go.uber.org/atomic v1.10.0
	go.uber.org/automaxprocs v1.5.1
	golang.org/x/crypto v0.5.0
	golang.org/x/exp v0.0.0-20221031165847-c99f073a8326
	golang.org/x/net v0.5.0
	golang.org/x/sync v0.1.0
	golang.org/x/sys v0.4.0
	gopkg.in/yaml.v3 v3.0.1
	lukechampine.com/blake3 v1.1.7
)

require (
	github.com/ajg/form v1.5.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/go-task/slim-sprig v0.0.0-20210107165309-348f09dbbbc0 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/pprof v0.0.0-20210407192527-94a9f03dee38 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/klauspost/cpuid/v2 v2.1.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/marten-seemann/qtls-go1-18 v0.1.3 // indirect
	github.com/marten-seemann/qtls-go1-19 v0.1.1 // indirect
	github.com/mdlayher/socket v0.4.0 // indirect
	github.com/onsi/ginkgo/v2 v2.2.0 // indirect
	github.com/oschwald/maxminddb-golang v1.10.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/sagernet/abx-go v0.0.0-20220819185957-dba1257d738e // indirect
	github.com/sagernet/go-tun2socks v1.16.12-0.20220818015926-16cb67876a61 // indirect
	github.com/u-root/uio v0.0.0-20221213070652-c3537552635f // indirect
	github.com/vishvananda/netns v0.0.1 // indirect
	golang.org/x/mod v0.6.0 // indirect
	golang.org/x/text v0.6.0 // indirect
	golang.org/x/time v0.1.0 // indirect
	golang.org/x/tools v0.2.0 // indirect
	gvisor.dev/gvisor v0.0.0-20230128000341-b7014294633b // indirect
)

replace gvisor.dev/gvisor v0.0.0-20230128000341-b7014294633b => github.com/metacubex/gvisor v0.0.0-20230129142733-94bf62304db8
