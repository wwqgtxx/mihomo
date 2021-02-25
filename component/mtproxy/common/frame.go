package common

import (
	"crypto/rand"
)

const (
	FrameLenKey   = 32
	FrameLenIV    = 16
	FrameLenMagic = 4
	FrameLenDC    = 2

	FrameOffsetFirst = 8
	FrameOffsetKey   = FrameOffsetFirst + FrameLenKey
	FrameOffsetIV    = FrameOffsetKey + FrameLenIV
	FrameOffsetMagic = FrameOffsetIV + FrameLenMagic
	FrameOffsetDC    = FrameOffsetMagic + FrameLenDC

	FrameLen = 64
)

// [FrameOffsetFirst:FrameOffsetKey:FrameOffsetIV:FrameOffsetMagic:FrameOffsetDC:frameOffsetEnd].
type ServerFrame struct {
	data [FrameLen]byte
}

func (f *ServerFrame) Bytes() []byte {
	return f.data[:]
}

func (f *ServerFrame) Key() []byte {
	return f.data[FrameOffsetFirst:FrameOffsetKey]
}

func (f *ServerFrame) IV() []byte {
	return f.data[FrameOffsetKey:FrameOffsetIV]
}

func (f *ServerFrame) Magic() []byte {
	return f.data[FrameOffsetIV:FrameOffsetMagic]
}

func (f *ServerFrame) DC() []byte {
	return f.data[FrameOffsetMagic:FrameOffsetDC]
}

func (f *ServerFrame) Unique() []byte {
	return f.data[FrameOffsetFirst:FrameOffsetDC]
}

func (f *ServerFrame) Invert() (nf ServerFrame) {
	nf = *f
	for i := 0; i < FrameLenKey+FrameLenIV; i++ {
		nf.data[FrameOffsetFirst+i] = f.data[FrameOffsetIV-1-i]
	}

	return
}

func GenerateFrame(ct ConnectionType) (fm ServerFrame) {
	data := fm.Bytes()

	for {
		if _, err := rand.Read(data); err != nil {
			continue
		}

		if data[0] == 0xef {
			continue
		}

		val := (uint32(data[3]) << 24) | (uint32(data[2]) << 16) | (uint32(data[1]) << 8) | uint32(data[0])
		if val == 0x44414548 || val == 0x54534f50 || val == 0x20544547 || val == 0x4954504f || val == 0xeeeeeeee {
			continue
		}

		val = (uint32(data[7]) << 24) | (uint32(data[6]) << 16) | (uint32(data[5]) << 8) | uint32(data[4])
		if val == 0x00000000 {
			continue
		}

		copy(fm.Magic(), ct.Tag())

		return
	}
}
