module github.com/Dreamacro/clash

go 1.19

require (
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da
	github.com/go-chi/chi/v5 v5.0.7
	github.com/go-chi/cors v1.2.1
	github.com/go-chi/render v1.0.2
	github.com/gofrs/uuid v4.3.1+incompatible
	github.com/gorilla/websocket v1.5.0
	github.com/insomniacslk/dhcp v0.0.0-20221001123530-5308ebe5334c
	github.com/jpillora/backoff v1.0.0
	github.com/kentik/patricia v1.2.0
	github.com/mdlayher/netlink v1.6.2
	github.com/metacubex/sing-wireguard v0.0.0-20221109114053-16c22adda03c
	github.com/miekg/dns v1.1.50
	github.com/oschwald/geoip2-golang v1.8.0
	github.com/sagernet/netlink v0.0.0-20220905062125-8043b4a9aa97
	github.com/sagernet/sing v0.0.0-20221008120626-60a9910eefe4
	github.com/sagernet/sing-shadowsocks v0.0.0-20221112030934-e55284e180ea
	github.com/sagernet/sing-tun v0.0.0-20221104121441-66c48a57776f
	github.com/sagernet/sing-vmess v0.0.0-20221109021549-b446d5bdddf0
	github.com/sagernet/wireguard-go v0.0.0-20221108054404-7c2acadba17c
	github.com/sirupsen/logrus v1.9.0
	github.com/stretchr/testify v1.8.1
	go.etcd.io/bbolt v1.3.6
	go.uber.org/atomic v1.10.0
	go.uber.org/automaxprocs v1.5.1
	golang.org/x/crypto v0.2.0
	golang.org/x/exp v0.0.0-20221031165847-c99f073a8326
	golang.org/x/net v0.2.0
	golang.org/x/sync v0.1.0
	golang.org/x/sys v0.2.0
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/sagernet/sing-tun => github.com/MetaCubeX/sing-tun v0.0.0-20221105124245-542e9b56a6dc

replace github.com/sagernet/sing-shadowsocks => github.com/MetaCubeX/sing-shadowsocks v0.0.0-20221116103607-48a7095182b1

require (
	github.com/ajg/form v1.5.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/josharian/native v1.0.0 // indirect
	github.com/klauspost/cpuid/v2 v2.1.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mdlayher/socket v0.2.3 // indirect
	github.com/oschwald/maxminddb-golang v1.10.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/sagernet/abx-go v0.0.0-20220819185957-dba1257d738e // indirect
	github.com/sagernet/go-tun2socks v1.16.12-0.20220818015926-16cb67876a61 // indirect
	github.com/u-root/uio v0.0.0-20220204230159-dac05f7d2cb4 // indirect
	github.com/vishvananda/netns v0.0.1 // indirect
	golang.org/x/mod v0.6.0 // indirect
	golang.org/x/text v0.4.0 // indirect
	golang.org/x/time v0.1.0 // indirect
	golang.org/x/tools v0.2.0 // indirect
	gvisor.dev/gvisor v0.0.0-20220901235040-6ca97ef2ce1c // indirect
	lukechampine.com/blake3 v1.1.7 // indirect
)
