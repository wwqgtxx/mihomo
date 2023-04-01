module github.com/Dreamacro/clash

go 1.20

require (
	github.com/3andne/restls-client-go v0.1.4
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da
	github.com/go-chi/chi/v5 v5.0.8
	github.com/go-chi/cors v1.2.1
	github.com/go-chi/render v1.0.2
	github.com/gofrs/uuid/v5 v5.0.0
	github.com/gorilla/websocket v1.5.0
	github.com/insomniacslk/dhcp v0.0.0-20230307103557-e252950ab961
	github.com/jpillora/backoff v1.0.0
	github.com/kentik/patricia v1.2.0
	github.com/mdlayher/netlink v1.7.2-0.20221213171556-9881fafed8c7
	github.com/metacubex/quic-go v0.33.2
	github.com/metacubex/sing-shadowsocks v0.1.1-0.20230226153717-4e80da7e6947
	github.com/metacubex/sing-tun v0.1.3-0.20230323115055-7935ba0ac8b3
	github.com/metacubex/sing-wireguard v0.0.0-20230310035749-f7595fcae5cb
	github.com/miekg/dns v1.1.52
	github.com/openacid/low v0.1.21
	github.com/oschwald/geoip2-golang v1.8.0
	github.com/sagernet/netlink v0.0.0-20220905062125-8043b4a9aa97
	github.com/sagernet/sing v0.2.1-0.20230323071235-f8038854d286
	github.com/sagernet/sing-shadowtls v0.1.0
	github.com/sagernet/sing-vmess v0.1.3
	github.com/sagernet/tfo-go v0.0.0-20230303015439-ffcfd8c41cf9
	github.com/sagernet/wireguard-go v0.0.0-20221116151939-c99467f53f2c
	github.com/samber/lo v1.37.0
	github.com/sirupsen/logrus v1.9.0
	github.com/stretchr/testify v1.8.2
	github.com/zhangyunhao116/fastrand v0.3.0
	go.etcd.io/bbolt v1.3.7
	go.uber.org/atomic v1.10.0
	go.uber.org/automaxprocs v1.5.2
	golang.org/x/crypto v0.7.0
	golang.org/x/exp v0.0.0-20230321023759-10a507213a29
	golang.org/x/net v0.8.0
	golang.org/x/sync v0.1.0
	golang.org/x/sys v0.6.0
	gopkg.in/yaml.v3 v3.0.1
	lukechampine.com/blake3 v1.1.7
)

require (
	github.com/ajg/form v1.5.1 // indirect
	github.com/andybalholm/brotli v1.0.4 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/go-task/slim-sprig v0.0.0-20210107165309-348f09dbbbc0 // indirect
	github.com/gofrs/uuid v4.4.0+incompatible // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/pprof v0.0.0-20210407192527-94a9f03dee38 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/klauspost/compress v1.15.15 // indirect
	github.com/klauspost/cpuid/v2 v2.1.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mdlayher/socket v0.4.0 // indirect
	github.com/metacubex/gvisor v0.0.0-20230323114922-412956fb6a03 // indirect
	github.com/onsi/ginkgo/v2 v2.2.0 // indirect
	github.com/oschwald/maxminddb-golang v1.10.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.14 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qtls-go1-19 v0.2.1 // indirect
	github.com/quic-go/qtls-go1-20 v0.1.1 // indirect
	github.com/sagernet/go-tun2socks v1.16.12-0.20220818015926-16cb67876a61 // indirect
	github.com/u-root/uio v0.0.0-20230220225925-ffce2a382923 // indirect
	github.com/vishvananda/netns v0.0.1 // indirect
	golang.org/x/mod v0.8.0 // indirect
	golang.org/x/text v0.8.0 // indirect
	golang.org/x/time v0.1.0 // indirect
	golang.org/x/tools v0.6.0 // indirect
)

replace go.uber.org/atomic v1.10.0 => github.com/metacubex/uber-atomic v0.0.0-20230202125923-feb10b770370
