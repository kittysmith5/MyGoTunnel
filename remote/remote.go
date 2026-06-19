package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const listenAddr = ":19001"

func main() {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		panic(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	ln, err := tls.Listen("tcp", ":9001", tlsConfig)
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
