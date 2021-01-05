package mmdb

import (
	_ "embed"
	"sync"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"

	"github.com/oschwald/geoip2-golang"
)

//go:embed Country.mmdb
var EmbedMMDB []byte

var mmdb *geoip2.Reader
var once sync.Once

func LoadFromBytes(buffer []byte) {
	once.Do(func() {
		var err error
		mmdb, err = geoip2.FromBytes(buffer)
		if err != nil {
			log.Fatalln("Can't load mmdb: %s", err.Error())
		}
	})
}

func getInstance() (instance *geoip2.Reader, err error) {
	if path := C.Path.MMDB(); path == "embed" {
		instance, err = geoip2.FromBytes(EmbedMMDB)
	} else {
		instance, err = geoip2.Open(C.Path.MMDB())
	}

	return
}

func Verify() bool {
	instance, err := getInstance()
	if err == nil {
		instance.Close()
	}
	return err == nil
}

func Instance() *geoip2.Reader {
	once.Do(func() {
		var err error
		mmdb, err = getInstance()

		if err != nil {
			log.Fatalln("Can't load mmdb: %s", err.Error())
		}
	})

	return mmdb
}
