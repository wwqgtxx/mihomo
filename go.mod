module github.com/wwqgtxx/clashr

go 1.14

require (
	github.com/Dreamacro/go-shadowsocks2 v0.1.5
	github.com/eapache/queue v1.1.0 // indirect
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/go-chi/cors v1.1.1
	github.com/go-chi/render v1.0.1
	github.com/gofrs/uuid v3.3.0+incompatible
	github.com/gorilla/websocket v1.4.2
	github.com/miekg/dns v1.1.29
	github.com/oschwald/geoip2-golang v1.4.0
	github.com/sirupsen/logrus v1.6.0
	github.com/stretchr/testify v1.6.1
	github.com/wwqgtxx/gossr v0.1.5
	golang.org/x/crypto v0.0.0-20200604202706-70a84ac30bf9
	golang.org/x/net v0.0.0-20200602114024-627f9648deb9
	golang.org/x/sync v0.0.0-20200317015054-43a5402ce75a
	golang.org/x/sys v0.0.0-20200323222414-85ca7c5b95cd
	gopkg.in/eapache/channels.v1 v1.1.0
	gopkg.in/yaml.v2 v2.2.8
	gvisor.dev/gvisor v0.0.0-00010101000000-000000000000
)

replace gvisor.dev/gvisor => github.com/comzyh/gvisor v0.0.0-20200510171600-c4d4be34b573
