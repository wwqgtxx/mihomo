package common

import (
	"bytes"
	"crypto/cipher"
	"io"
)

type wrapperObfuscated2 struct {
	encryptor cipher.Stream
	decryptor cipher.Stream
	parent    io.ReadWriteCloser
}

func (w *wrapperObfuscated2) Read(p []byte) (int, error) {
	n, err := w.parent.Read(p)
	if err != nil {
		return n, err
	}

	w.decryptor.XORKeyStream(p, p[:n])

	return n, nil
}

func (w *wrapperObfuscated2) Write(p []byte) (int, error) {
	buffer := bytes.Buffer{}

	buffer.Write(p)

	buf := buffer.Bytes()

	w.encryptor.XORKeyStream(buf, buf)

	return w.parent.Write(buf)
}

func (w *wrapperObfuscated2) Close() error {
	return w.parent.Close()
}

func NewObfuscated2(socket io.ReadWriteCloser, encryptor, decryptor cipher.Stream) io.ReadWriteCloser {
	return &wrapperObfuscated2{
		parent:    socket,
		encryptor: encryptor,
		decryptor: decryptor,
	}
}
