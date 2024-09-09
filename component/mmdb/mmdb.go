package mmdb

import (
	_ "embed"
	"sync"

	mihomoOnce "github.com/metacubex/mihomo/common/once"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/oschwald/maxminddb-golang"
)

type databaseType = uint8

const (
	typeMaxmind databaseType = iota
	typeSing
	typeMetaV0
)

var (
	//go:embed Country.mmdb
	EmbedMMDB []byte
	ipReader  IPReader
	ipOnce    sync.Once
)

func LoadFromBytes(buffer []byte) {
	ipOnce.Do(func() {
		mmdb, err := maxminddb.FromBytes(buffer)
		if err != nil {
			log.Fatalln("Can't load mmdb: %s", err.Error())
		}
		ipReader = IPReader{Reader: mmdb}
		switch mmdb.Metadata.DatabaseType {
		case "sing-geoip":
			ipReader.databaseType = typeSing
		case "Meta-geoip0":
			ipReader.databaseType = typeMetaV0
		default:
			ipReader.databaseType = typeMaxmind
		}
	})
}

func getMmdbReader() (instance *maxminddb.Reader, err error) {
	if mmdbPath := C.Path.MMDB(); mmdbPath == "embed" {
		instance, err = maxminddb.FromBytes(EmbedMMDB)
	} else {
		log.Infoln("Load MMDB file: %s", mmdbPath)
		instance, err = maxminddb.Open(C.Path.MMDB())
	}

	return
}

func Verify() bool {
	instance, err := getMmdbReader()
	if err == nil {
		instance.Close()
	}
	return err == nil
}

func IPInstance() IPReader {
	ipOnce.Do(func() {
		mmdb, err := getMmdbReader()
		if err != nil {
			log.Fatalln("Can't load MMDB: %s", err.Error())
		}
		ipReader = IPReader{Reader: mmdb}
		switch mmdb.Metadata.DatabaseType {
		case "sing-geoip":
			ipReader.databaseType = typeSing
		case "Meta-geoip0":
			ipReader.databaseType = typeMetaV0
		default:
			ipReader.databaseType = typeMaxmind
		}
	})

	return ipReader
}

func ReloadIP() {
	mihomoOnce.Reset(&ipOnce)
}
