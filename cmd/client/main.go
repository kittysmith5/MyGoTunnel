package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net"

	"mygotunnel/internal/config"
	"mygotunnel/internal/mux"
	"mygotunnel/internal/relay"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
)

func main() {
	configPath := flag.String("config", "configs/client.json", "config file path")
	flag.Parse()

	cfg, err := config.LoadClientConfig(*configPath)
	if err != nil {
		fmt.Println("[client] load config error:", err)
		return
	}

	// 1. 启动时建立一个长期 mux session
	sess, err := dialMuxSession(cfg)
	if err != nil {
		fmt.Println("[client] dial mux session error:", err)
		return
	}
	defer sess.Close()

	// 2. 本地启动 SOCKS5 监听
	ln, err := net.Listen("tcp", cfg.LocalAddr)
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	fmt.Println("[client] SOCKS5 listening on", cfg.LocalAddr)
	fmt.Println("[client] remote node:", cfg.RemoteAddr)
	fmt.Println("[client] mux session ready")

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("[client] accept error:", err)
			continue
		}

		go handleClient(conn, sess)
	}
}

func dialMuxSession(cfg *config.ClientConfig) (*mux.Session, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	remoteConn, err := tls.Dial("tcp", cfg.RemoteAddr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("dial remote failed: %w", err)
	}

	reader := bufio.NewReader(remoteConn)

	// 1. AUTH 只做一次
	if err := tunnel.SendAuth(remoteConn, cfg.AuthToken); err != nil {
		_ = remoteConn.Close()
		return nil, fmt.Errorf("send auth failed: %w", err)
	}

	resp, err := tunnel.ReadLine(reader)
	if err != nil {
		_ = remoteConn.Close()
		return nil, fmt.Errorf("read auth response failed: %w", err)
	}

	if resp != "OK" {
		_ = remoteConn.Close()
		return nil, fmt.Errorf("auth failed: %s", resp)
	}

	// 2. AUTH OK 后，把 TLS 连接交给 mux
	sess := mux.NewSession(remoteConn, mux.ModeClient)

	return sess, nil
}

func handleClient(clientConn net.Conn, sess *mux.Session) {
	defer clientConn.Close()

	clientAddr := clientConn.RemoteAddr().String()
	fmt.Println("[client] socks5 client connected:", clientAddr)

	// 1. SOCKS5 握手
	if err := socks5.Handshake(clientConn); err != nil {
		fmt.Println("[client] socks5 handshake error:", err)
		return
	}

	// 2. 读取 SOCKS5 CONNECT 请求
	targetAddr, err := socks5.ReadRequest(clientConn)
	if err != nil {
		fmt.Println("[client] socks5 request error:", err)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}

	fmt.Println("[client] target:", targetAddr)

	// 3. 为这个 SOCKS5 请求打开一个 mux stream
	stream, err := sess.OpenStream()
	if err != nil {
		fmt.Println("[client] open stream error:", err)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}
	defer stream.Close()

	fmt.Printf("[client] open stream %d for %s\n", stream.ID(), targetAddr)

	streamReader := bufio.NewReader(stream)

	// 4. 在 stream 里发送 CONNECT target
	if err := tunnel.SendConnect(stream, targetAddr); err != nil {
		fmt.Println("[client] send stream CONNECT error:", err)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}

	// 5. 等 server 返回 OK
	resp, err := tunnel.ReadLine(streamReader)
	if err != nil {
		fmt.Println("[client] read stream response error:", err)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}

	if resp != "OK" {
		fmt.Println("[client] remote connect failed:", resp)
		_ = socks5.Reply(clientConn, 0x05)
		return
	}

	// 6. 回复浏览器：SOCKS5 CONNECT 成功
	if err := socks5.Reply(clientConn, 0x00); err != nil {
		fmt.Println("[client] socks5 reply error:", err)
		return
	}

	// 7. clientConn <-> mux stream 双向转发
	relay.CopyBidirectional(clientConn, clientConn, stream, streamReader)

	fmt.Println("[client] client closed:", clientAddr)
}
