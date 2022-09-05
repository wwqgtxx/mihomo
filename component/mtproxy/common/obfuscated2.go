package common

import (
	"bytes"
	"crypto/cipher"
	"net"
)

type wrapperObfuscated2 struct {
	net.Conn
	encryptor cipher.Stream
	decryptor cipher.Stream
}

func (w *wrapperObfuscated2) Read(p []byte) (int, error) {
	n, err := w.Conn.Read(p)
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

	return w.Conn.Write(buf)
}

func (w *wrapperObfuscated2) Close() error {
	return w.Conn.Close()
}

func NewObfuscated2(socket net.Conn, encryptor, decryptor cipher.Stream) net.Conn {
	return &wrapperObfuscated2{
		Conn:      socket,
		encryptor: encryptor,
		decryptor: decryptor,
	}
}
