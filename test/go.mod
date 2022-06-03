module clash-test

go 1.18

require (
	github.com/Dreamacro/clash v0.0.0 // local
	github.com/docker/docker v20.10.16+incompatible
	github.com/docker/go-connections v0.4.0
	github.com/miekg/dns v1.1.49
	github.com/stretchr/testify v1.7.1
	golang.org/x/net v0.0.0-20220520000938-2e3eb7b945c2
)

require (
	github.com/Microsoft/go-winio v0.5.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/docker/distribution v2.8.1+incompatible // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/gofrs/uuid v4.2.0+incompatible // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/btree v1.0.1 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/insomniacslk/dhcp v0.0.0-20220504074936-1ca156eafb9f // indirect
	github.com/kentik/patricia v1.0.0 // indirect
	github.com/moby/term v0.0.0-20210619224110-3f7ff695adc6 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/oschwald/geoip2-golang v1.7.0 // indirect
	github.com/oschwald/maxminddb-golang v1.9.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/u-root/uio v0.0.0-20220204230159-dac05f7d2cb4 // indirect
	go.etcd.io/bbolt v1.3.6 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	golang.org/x/crypto v0.0.0-20220507011949-2cf3adece122 // indirect
	golang.org/x/mod v0.6.0-dev.0.20220419223038-86c51ed26bb4 // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c // indirect
	golang.org/x/sys v0.0.0-20220503163025-988cb79eb6c6 // indirect
	golang.org/x/text v0.3.8-0.20220504184655-ea49e3e2d5b3 // indirect
	golang.org/x/time v0.0.0-20220411224347-583f2d630306 // indirect
	golang.org/x/tools v0.1.11-0.20220506163328-22b709631a03 // indirect
	golang.zx2c4.com/wireguard/windows v0.5.3 // indirect
	gopkg.in/yaml.v3 v3.0.0 // indirect
	gotest.tools/v3 v3.2.0 // indirect
	gvisor.dev/gvisor v0.0.0-20220506231117-8ef340c14150 // indirect
)

replace github.com/Dreamacro/clash => ../
