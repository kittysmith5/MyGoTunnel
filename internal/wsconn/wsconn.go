package wsconn

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	utls "github.com/refraction-networking/utls"
)

const binaryMessage = websocket.MessageBinary

func Dial(ctx context.Context, remoteAddr, path, sni string) (net.Conn, error) {
	wsURL := buildURL(remoteAddr, path)
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialUTLS(ctx, network, addr, sni)
		},
	}

	headers := browserHeaders(wsURL, sni)
	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPClient: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
		},
		HTTPHeader: headers,
		Host:       hostHeader(wsURL, sni),
	})
	if err != nil {
		return nil, err
	}

	return websocket.NetConn(context.Background(), conn, binaryMessage), nil
}

func dialUTLS(ctx context.Context, network, addr, sni string) (net.Conn, error) {
	dialer := &net.Dialer{}
	tcpConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	serverName := sni
	if serverName == "" {
		serverName = serverNameFromAddr(addr)
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

func browserHeaders(wsURL, sni string) http.Header {
	return http.Header{
		"User-Agent":      []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"},
		"Accept-Language": []string{"en-US,en;q=0.9"},
		"Accept-Encoding": []string{"gzip, deflate, br"},
		"Cache-Control":   []string{"no-cache"},
		"Pragma":          []string{"no-cache"},
		"Origin":          []string{originHeader(wsURL, sni)},
	}
}

func Accept(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}

	return websocket.NetConn(context.Background(), conn, binaryMessage), nil
}

func buildURL(remoteAddr, path string) string {
	if strings.HasPrefix(remoteAddr, "ws://") || strings.HasPrefix(remoteAddr, "wss://") {
		return remoteAddr
	}

	if path == "" {
		path = "/tunnel"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return fmt.Sprintf("wss://%s%s", remoteAddr, path)
}

func hostHeader(wsURL, sni string) string {
	if sni != "" {
		return sni
	}

	host := strings.TrimPrefix(wsURL, "wss://")
	host = strings.TrimPrefix(host, "ws://")
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	return host
}

func originHeader(wsURL, sni string) string {
	scheme := "https"
	if strings.HasPrefix(wsURL, "ws://") {
		scheme = "http"
	}

	return fmt.Sprintf("%s://%s", scheme, hostHeader(wsURL, sni))
}

func serverNameFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	return strings.Trim(host, "[]")
}
