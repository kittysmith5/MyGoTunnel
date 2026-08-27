package utlsconn

import (
	"context"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"
)

type closeWriter interface {
	CloseWrite() error
}

var _ closeWriter = (*utls.UConn)(nil)

func Dial(ctx context.Context, remoteAddr, sni string) (net.Conn, error) {
	dialer := &net.Dialer{}
	tcpConn, err := dialer.DialContext(ctx, "tcp", remoteAddr)
	if err != nil {
		return nil, err
	}

	serverName := sni
	if serverName == "" {
		serverName = serverNameFromAddr(remoteAddr)
	}

	tlsConn := utls.UClient(tcpConn, &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	}, utls.HelloChrome_Auto)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

func serverNameFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	return strings.Trim(host, "[]")
}
