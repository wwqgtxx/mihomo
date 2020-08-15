module github.com/Dreamacro/clash

go 1.14

require (
	github.com/Dreamacro/go-shadowsocks2 v0.1.6-0.20200722122336-8e5c7db4f96a
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
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/net v0.0.0-20200625001655-4c5254603344
	golang.org/x/sync v0.0.0-20200625203802-6e8e738ad208
	golang.org/x/sys v0.0.0-20200323222414-85ca7c5b95cd
	gopkg.in/eapache/channels.v1 v1.1.0
	gopkg.in/yaml.v2 v2.3.0
	gvisor.dev/gvisor v0.0.0-00010101000000-000000000000
)

replace gvisor.dev/gvisor => github.com/comzyh/gvisor v0.0.0-20200814151311-224de3a00460
