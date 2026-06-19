package main

import (
	"bufio"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// const listenAddr = ":9001"

type Config struct {
	LocalPort string `json:"local_port"`
	AuthToken string `json:"auth_token"`
}

var authToken = ""
var listenAddr = ""

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config failed: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config failed: %w", err)
	}

	if cfg.LocalPort == "" {
		listenAddr = ":9001"
	} else {
		listenAddr = cfg.LocalPort
	}

	if cfg.AuthToken == "" {
		return nil, fmt.Errorf("auth_token is empty")
	} else {
		authToken = cfg.AuthToken
	}
	return &cfg, nil
}

func checkAuth(conn net.Conn, reader *bufio.Reader, expectedToken string) bool {
	// 防止客户端连上后一直不发 AUTH，占着连接
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	line, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	line = strings.TrimSpace(line)

	if !strings.HasPrefix(line, "AUTH ") {
		_, _ = conn.Write([]byte("ERR\n"))
		return false
	}

	clientToken := strings.TrimSpace(strings.TrimPrefix(line, "AUTH "))

	// 使用 constant-time compare，避免时序侧信道
	if subtle.ConstantTimeCompare([]byte(clientToken), []byte(expectedToken)) != 1 {
		_, _ = conn.Write([]byte("ERR\n"))
		return false
	}

	_, _ = conn.Write([]byte("OK\n"))
	return true
}

func main() {
	configPath := flag.String("config", "config.json", "config file path")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Println("[client] load config error:", err)
		return
	}

	fmt.Println("[client] local port :", cfg.LocalPort)
	fmt.Println("[client] auth token:", cfg.AuthToken)

	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		panic(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	ln, err := tls.Listen("tcp", listenAddr, tlsConfig)
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	fmt.Println("[remote] listening on", listenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("[remote] accept error:", err)
			continue
		}

		go handleTunnel(conn)
	}
}

func handleTunnel(tunnelConn net.Conn) {
	defer tunnelConn.Close()

	remoteAddr := tunnelConn.RemoteAddr().String()
	fmt.Println("[remote] tunnel connected:", remoteAddr)

	reader := bufio.NewReader(tunnelConn)

	// 1. 先做 AUTH
	if !checkAuth(tunnelConn, reader, authToken) {
		fmt.Println("[remote] auth failed:", remoteAddr)
		return
	}
	fmt.Println("[remote] auth success:", remoteAddr)
	// 1. 读取 LocalProxy 发来的 CONNECT 请求
	line, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("[remote] read connect line error:", err)
		return
	}

	line = strings.TrimSpace(line)

	if !strings.HasPrefix(line, "CONNECT ") {
		fmt.Println("[remote] invalid command:", line)
		return
	}

	targetAddr := strings.TrimSpace(strings.TrimPrefix(line, "CONNECT "))
	if targetAddr == "" {
		fmt.Println("[remote] empty target addr")
		return
	}

	fmt.Println("[remote] connect target:", targetAddr)

	// 2. 远端节点连接最终目标
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		fmt.Println("[remote] dial target error:", err)
		_, _ = tunnelConn.Write([]byte("ERR\n"))
		return
	}
	defer targetConn.Close()

	// 3. 告诉 LocalProxy：目标连接成功
	_, err = tunnelConn.Write([]byte("OK\n"))
	if err != nil {
		fmt.Println("[remote] write OK error:", err)
		return
	}

	// 4. 双向转发
	// 注意：这里 client -> target 方向要从 reader 读，而不是 tunnelConn。
	// 因为 bufio.Reader 可能已经预读了一部分数据。
	errCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(targetConn, reader)
		closeWrite(targetConn)
		errCh <- err
	}()

	go func() {
		_, err := io.Copy(tunnelConn, targetConn)
		closeWrite(tunnelConn)
		errCh <- err
	}()

	<-errCh

	fmt.Println("[remote] tunnel closed:", remoteAddr)
}

func closeWrite(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
	}
}
