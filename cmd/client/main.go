package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/relay"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
	"mygotunnel/internal/wsconn"
)

func main() {
	configPath := flag.String("config", "configs/client.json", "config file path")
	flag.Parse()

	cfg, err := config.LoadClientConfig(*configPath)
	if err != nil {
		fmt.Println("[client] load config error:", err)
		return
	}

	ln, err := net.Listen("tcp", cfg.LocalAddr)
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	fmt.Println("[client] SOCKS5 listening on", cfg.LocalAddr)
	fmt.Println("[client] remote WebSocket node:", cfg.RemoteAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("[client] accept error:", err)
			continue
		}

		go handleClient(conn, cfg)
	}
}

func handleClient(clientConn net.Conn, cfg *config.ClientConfig) {
	defer clientConn.Close()

	clientAddr := clientConn.RemoteAddr().String()
	fmt.Println("[client] connected:", clientAddr)

	if err := socks5.Handshake(clientConn); err != nil {
		fmt.Println("[client] socks5 handshake error:", err)
		return
	}

	targetAddr, err := socks5.ReadRequest(clientConn)
	if err != nil {
		fmt.Println("[client] socks5 request error:", err)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}

	fmt.Println("[client] target:", targetAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	remoteConn, err := wsconn.Dial(ctx, cfg.RemoteAddr, cfg.WSPath)
	cancel()
	if err != nil {
		fmt.Println("[client] dial remote WebSocket error:", err)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}
	defer remoteConn.Close()

	remoteReader := bufio.NewReader(remoteConn)

	if err := tunnel.SendAuth(remoteConn, cfg.AuthToken); err != nil {
		fmt.Println("[client] send auth error:", err)
		return
	}

	authResp, err := tunnel.ReadLine(remoteReader)
	if err != nil {
		fmt.Println("[client] read auth response error:", err)
		return
	}

	if authResp != "OK" {
		fmt.Println("[client] auth failed:", authResp)
		return
	}

	if err := tunnel.SendConnect(remoteConn, targetAddr); err != nil {
		fmt.Println("[client] send connect error:", err)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}

	resp, err := tunnel.ReadLine(remoteReader)
	if err != nil {
		fmt.Println("[client] read remote response error:", err)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}

	if resp != "OK" {
		fmt.Println("[client] remote connect failed:", resp)
		_ = socks5.Reply(clientConn, 0x05)
		return
	}

	if err := socks5.Reply(clientConn, 0x00); err != nil {
		fmt.Println("[client] socks5 reply error:", err)
		return
	}

	relay.CopyBidirectional(clientConn, clientConn, remoteConn, remoteReader)

	fmt.Println("[client] closed:", clientAddr)
}
