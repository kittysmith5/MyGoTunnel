package main

import (
	"bufio"
	"crypto/subtle"
	"flag"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/relay"
	"mygotunnel/internal/tunnel"
	"mygotunnel/internal/wsconn"
)

func main() {
	configPath := flag.String("config", "configs/server.json", "config file path")
	flag.Parse()

	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		fmt.Println("[server] load config error:", err)
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc(cfg.WSPath, func(w http.ResponseWriter, r *http.Request) {
		if !isWebSocketRequest(r) {
			serveFallback(w, r)
			return
		}

		conn, err := wsconn.Accept(w, r)
		if err != nil {
			fmt.Println("[server] websocket accept error:", err)
			return
		}

		go handleTunnel(conn, cfg)
	})
	mux.HandleFunc("/", serveFallback)

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Println("[server] WebSocket listening on", cfg.ListenAddr, "path", cfg.WSPath)
	if err := server.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile); err != nil {
		panic(err)
	}
}

func isWebSocketRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func serveFallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "max-age=300")
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Welcome</title>
</head>
<body>
  <h1>Welcome</h1>
</body>
</html>`))
}

func handleTunnel(tunnelConn net.Conn, cfg *config.ServerConfig) {
	defer tunnelConn.Close()

	remoteAddr := tunnelConn.RemoteAddr().String()
	fmt.Println("[server] tunnel connected:", remoteAddr)

	reader := bufio.NewReader(tunnelConn)

	if !checkAuth(tunnelConn, reader, cfg.AuthToken) {
		fmt.Println("[server] auth failed:", remoteAddr)
		return
	}

	line, err := tunnel.ReadLine(reader)
	if err != nil {
		fmt.Println("[server] read connect line error:", err)
		return
	}

	if !strings.HasPrefix(line, "CONNECT ") {
		fmt.Println("[server] invalid command:", line)
		return
	}

	targetAddr := strings.TrimSpace(strings.TrimPrefix(line, "CONNECT "))
	if targetAddr == "" {
		fmt.Println("[server] empty target addr")
		return
	}

	fmt.Println("[server] connect target:", targetAddr)

	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		fmt.Println("[server] dial target error:", err)
		_ = tunnel.SendERR(tunnelConn)
		return
	}
	defer targetConn.Close()

	if err := tunnel.SendOK(tunnelConn); err != nil {
		fmt.Println("[server] send OK error:", err)
		return
	}

	relay.CopyBidirectional(tunnelConn, reader, targetConn, targetConn)

	fmt.Println("[server] tunnel closed:", remoteAddr)
}

func checkAuth(conn net.Conn, reader *bufio.Reader, expectedToken string) bool {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	line, err := tunnel.ReadLine(reader)
	if err != nil {
		return false
	}

	if !strings.HasPrefix(line, "AUTH ") {
		_ = tunnel.SendERR(conn)
		return false
	}

	clientToken := strings.TrimSpace(strings.TrimPrefix(line, "AUTH "))

	if subtle.ConstantTimeCompare([]byte(clientToken), []byte(expectedToken)) != 1 {
		_ = tunnel.SendERR(conn)
		return false
	}

	_ = tunnel.SendOK(conn)
	return true
}
