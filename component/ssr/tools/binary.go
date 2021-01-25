package tools

import (
	"math/rand"

	"github.com/Dreamacro/clash/common/pool"
)

const (
	BigEndian    = true
	LittleEndian = false
)

func AppendUint32LittleEndian(b []byte, v uint32) []byte {
	b = append(b, byte(v&0xff))
	b = append(b, byte((v>>8)&0xff))
	b = append(b, byte((v>>16)&0xff))
	b = append(b, byte((v>>24)&0xff))
	return b
}

func AppendUint16LittleEndian(b []byte, v uint16) []byte {
	b = append(b, byte(v&0xff))
	b = append(b, byte((v>>8)&0xff))
	return b
}

func AppendUint16BigEndian(b []byte, v uint16) []byte {
	b = append(b, byte((v>>8)&0xff))
	b = append(b, byte(v&0xff))
	return b
}

func AppendRandBytes(b []byte, length int) []byte {
	randBytes := pool.Get(length)
	defer pool.Put(randBytes)
	rand.Read(randBytes)
	return append(b, randBytes...)
}
