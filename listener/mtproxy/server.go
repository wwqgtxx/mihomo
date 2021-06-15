package mtproxy

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/Dreamacro/clash/component/mtproxy/common"
	"github.com/Dreamacro/clash/component/mtproxy/server_protocol"
	"github.com/Dreamacro/clash/component/mtproxy/tools"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/log"
)

const (
	FakeTLSFirstByte = server_protocol.FakeTLSFirstByte
)

func init() {
	common.PrintlnFunc = func(str string) {
		log.Warnln(str)
	}
}

type Listener struct {
	config     string
	closed     bool
	listeners  []net.Listener
	serverInfo *tools.ServerInfo
}

var _listener *Listener

func New(config string, in chan<- C.ConnContext) (*Listener, error) {
	if len(config) == 0 {
		return nil, nil
	}
	spliced := strings.Split(config, "@")
	addrString := ""
	if len(spliced) > 2 {
		return nil, errors.New("addr format error")
	}
	if len(spliced) > 1 {
		addrString = spliced[1]
	}

	spliced2 := strings.Split(spliced[0], ":")
	serverInfo, err := tools.ParseHexedSecret(spliced2[0])
	if err != nil {
		return nil, err
	}
	if len(spliced2) == 2 {
		serverInfo.CloakPort = spliced2[1]
	}

	hl := &Listener{
		config:     config,
		closed:     false,
		serverInfo: serverInfo,
	}

	_listener = hl

	if len(addrString) == 0 {
		return hl, nil
	}

	for _, addr := range strings.Split(addrString, ",") {
		addr := addr

		l, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		hl.listeners = append(hl.listeners, l)

		go func() {
			log.Infoln("MTProxy listening at: %s", addr)

			for {
				c, err := l.Accept()
				if err != nil {
					if hl.closed {
						break
					}
					continue
				}
				_ = c.(*net.TCPConn).SetKeepAlive(true)
				go hl.HandleConn(c, in)
			}
		}()
	}

	return hl, nil
}

func (l *Listener) Close() {
	l.closed = true
	for _, lis := range l.listeners {
		_ = lis.Close()
	}
}

func (l *Listener) Config() string {
	return l.config
}

func (l *Listener) SecretMode() common.SecretMode {
	return l.serverInfo.SecretMode
}

func (l *Listener) HandleConn(conn net.Conn, in chan<- C.ConnContext) {
	serverProtocol := l.serverInfo.ServerProtocolMaker(
		l.serverInfo.Secret,
		l.serverInfo.SecretMode,
		l.serverInfo.CloakHost,
		l.serverInfo.CloakPort,
	)
	serverConn, err := serverProtocol.Handshake(conn)
	if err != nil {
		//logger.Warnw("Cannot perform client handshake", "error", err)

		return
	}
	defer serverConn.Close()

	telegramConn, err := l.serverInfo.TelegramDialer.Dial(
		serverProtocol,
		func(addr string) (io.ReadWriteCloser, error) {
			conn1, conn2 := net.Pipe()
			host, port, _ := net.SplitHostPort(addr)
			remoteHost, remotePort, _ := net.SplitHostPort(conn.RemoteAddr().String())
			remoteIp := net.ParseIP(remoteHost)
			metadata := &C.Metadata{
				NetWork:  C.TCP,
				AddrType: C.AtypDomainName,
				Host:     host,
				DstIP:    nil,
				DstPort:  port,
				SrcIP:    remoteIp,
				SrcPort:  remotePort,
			}
			metadata.Type = C.MTPROXY
			if host, port, err := net.SplitHostPort(conn.LocalAddr().String()); err == nil {
				ip := net.ParseIP(host)
				metadata.InIP = ip
				metadata.InPort = port
			}
			connContext := context.NewConnContext(conn2, metadata)
			in <- connContext
			return conn1, nil
		})
	if err != nil {
		return
	}
	defer telegramConn.Close()

	wg := &sync.WaitGroup{}
	wg.Add(2)

	go directPipe(telegramConn, serverConn, wg)
	go directPipe(serverConn, telegramConn, wg)

	wg.Wait()
}

func directPipe(dst io.WriteCloser, src io.ReadCloser, wg *sync.WaitGroup) {
	defer wg.Done()
	_, _ = io.Copy(dst, src)
}

func HandleFakeTLS(conn net.Conn, in chan<- C.ConnContext) bool {
	if _listener != nil && _listener.SecretMode() == common.SecretModeTLS {
		go _listener.HandleConn(conn, in)
		return true
	}
	return false
}
