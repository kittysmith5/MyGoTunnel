package main

import (
	"bufio"
	"crypto/subtle"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"strings"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/relay"
	"mygotunnel/internal/tunnel"
)

func main() {
	configPath := flag.String("config", "configs/server.json", "config file path")
	flag.Parse()

	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		fmt.Println("[server] load config error:", err)
		return
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		panic(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	ln, err := tls.Listen("tcp", cfg.ListenAddr, tlsConfig)
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	fmt.Println("[server] listening on", cfg.ListenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("[server] accept error:", err)
			continue
		}

		go handleTunnel(conn, cfg)
	}
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
