package common

import (
	"net"
)

const SimpleSecretLength = 16

type DC int16

const DCDefaultIdx DC = 1

type ConnectionProtocol uint8

func (c ConnectionProtocol) String() string {
	switch c {
	case ConnectionProtocolAny:
		return "any"
	case ConnectionProtocolIPv4:
		return "ipv4"
	case ConnectionProtocolIPv6:
		return "ipv6"
	}

	return "ipv6"
}

const (
	ConnectionProtocolIPv4 ConnectionProtocol = 1
	ConnectionProtocolIPv6                    = ConnectionProtocolIPv4 << 1
	ConnectionProtocolAny                     = ConnectionProtocolIPv4 | ConnectionProtocolIPv6
)

type ConnectionType uint8

const (
	ConnectionTypeUnknown ConnectionType = iota
	ConnectionTypeAbridged
	ConnectionTypeIntermediate
	ConnectionTypeSecure
)

var (
	ConnectionTagAbridged     = []byte{0xef, 0xef, 0xef, 0xef}
	ConnectionTagIntermediate = []byte{0xee, 0xee, 0xee, 0xee}
	ConnectionTagSecure       = []byte{0xdd, 0xdd, 0xdd, 0xdd}
)

func (t ConnectionType) Tag() []byte {
	switch t {
	case ConnectionTypeAbridged:
		return ConnectionTagAbridged
	case ConnectionTypeIntermediate:
		return ConnectionTagIntermediate
	case ConnectionTypeSecure, ConnectionTypeUnknown:
		return ConnectionTagSecure
	}

	return ConnectionTagSecure
}

type SecretMode uint8

func (s SecretMode) String() string {
	switch s {
	case SecretModeSimple:
		return "simple"
	case SecretModeSecured:
		return "secured"
	case SecretModeTLS:
		return "tls"
	}

	return "tls"
}

const (
	SecretModeSimple SecretMode = iota
	SecretModeSecured
	SecretModeTLS
)

type ServerProtocol interface {
	Handshake(net.Conn) (net.Conn, error)
	ConnectionType() ConnectionType
	ConnectionProtocol() ConnectionProtocol
	DC() DC
}

type ServerProtocolMaker func(secret []byte, secretMode SecretMode, cloakHost string, cloakPort string) ServerProtocol

var PrintlnFunc = func(str string) {}
