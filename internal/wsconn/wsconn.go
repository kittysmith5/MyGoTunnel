package wsconn

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
)

const binaryMessage = websocket.MessageBinary

func Dial(ctx context.Context, remoteAddr, path string) (net.Conn, error) {
	wsURL := buildURL(remoteAddr, path)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPClient: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
		},
		HTTPHeader: http.Header{
			"User-Agent": []string{"Mozilla/5.0"},
		},
	})
	if err != nil {
		return nil, err
	}

	return websocket.NetConn(context.Background(), conn, binaryMessage), nil
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
