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
	"mygotunnel/internal/mux"
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

	// 1. TLS 连接建立后，先 AUTH 一次
	if !checkAuth(tunnelConn, reader, cfg.AuthToken) {
		fmt.Println("[server] auth failed:", remoteAddr)
		return
	}

	fmt.Println("[server] auth success:", remoteAddr)

	// 2. AUTH 成功后，这条 TLS 连接交给 mux 管理
	sess := mux.NewSession(tunnelConn, mux.ModeServer)
	defer sess.Close()

	fmt.Println("[server] mux session started:", remoteAddr)

	// 3. 一个 TLS 连接里循环接收多个逻辑 Stream
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			fmt.Println("[server] accept stream error:", err)
			return
		}

		fmt.Println("[server] accept stream:", stream.ID())

		go handleStream(stream)
	}
}

func handleStream(stream *mux.Stream) {
	defer stream.Close()

	reader := bufio.NewReader(stream)

	// 1. 每个 stream 里读取 CONNECT target
	line, err := tunnel.ReadLine(reader)
	if err != nil {
		fmt.Println("[server] read stream connect error:", err)
		return
	}

	if !strings.HasPrefix(line, "CONNECT ") {
		fmt.Println("[server] invalid stream command:", line)
		_ = tunnel.SendERR(stream)
		return
	}

	targetAddr := strings.TrimSpace(strings.TrimPrefix(line, "CONNECT "))
	if targetAddr == "" {
		fmt.Println("[server] empty target addr")
		_ = tunnel.SendERR(stream)
		return
	}

	fmt.Printf("[server] stream %d connect target: %s\n", stream.ID(), targetAddr)

	// 2. 远端连接真实目标
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		fmt.Println("[server] dial target error:", err)
		_ = tunnel.SendERR(stream)
		return
	}
	defer targetConn.Close()

	// 3. 告诉 client：目标连接成功
	if err := tunnel.SendOK(stream); err != nil {
		fmt.Println("[server] send OK error:", err)
		return
	}

	// 4. stream <-> targetConn 双向转发
	relay.CopyBidirectional(stream, reader, targetConn, targetConn)

	fmt.Println("[server] stream closed:", stream.ID())
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
