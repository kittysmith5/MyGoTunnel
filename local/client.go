package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	AuthToken  string `json:"auth_token"`
}

var remoteAddr string = ""
var authToken string = ""

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config failed: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config failed: %w", err)
	}

	if cfg.LocalAddr == "" {
		cfg.LocalAddr = "127.0.0.1:1080"
	}

	if cfg.RemoteAddr == "" {
		return nil, fmt.Errorf("remote_addr is empty")
	} else {
		remoteAddr = cfg.RemoteAddr
	}

	if cfg.AuthToken == "" {
		return nil, fmt.Errorf("auth_token is empty")
	} else {
		authToken = cfg.AuthToken
	}
	return &cfg, nil
}

func main() {
	configPath := flag.String("config", "config.json", "config file path")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Println("[client] load config error:", err)
		return
	}

	fmt.Println("[client] local addr :", cfg.LocalAddr)
	fmt.Println("[client] remote addr:", cfg.RemoteAddr)
	ln, err := net.Listen("tcp", cfg.LocalAddr)
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	fmt.Println("[local] SOCKS5 listening on", cfg.LocalAddr)
	fmt.Println("[local] remote node:", cfg.RemoteAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("[local] accept error:", err)
			continue
		}

		go handleClient(conn)
	}
}

func handleClient(clientConn net.Conn) {
	defer clientConn.Close()

	clientAddr := clientConn.RemoteAddr().String()
	fmt.Println("[local] client connected:", clientAddr)

	// 1. SOCKS5 握手
	if err := socks5Handshake(clientConn); err != nil {
		fmt.Println("[local] handshake error:", err)
		return
	}

	// 2. 解析 SOCKS5 CONNECT 请求
	targetAddr, err := socks5ReadRequest(clientConn)
	if err != nil {
		fmt.Println("[local] read request error:", err)
		_ = socks5Reply(clientConn, 0x01) // general failure
		return
	}

	fmt.Println("[local] request target:", targetAddr)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	// 3. 连接远端节点
	remoteConn, err := tls.Dial("tcp", remoteAddr, tlsConfig)
	if err != nil {
		fmt.Println("[local] dial remote error:", err)
		_ = socks5Reply(clientConn, 0x01)
		return
	}
	defer remoteConn.Close()

	// 4. 给远端节点发送自定义 tunnel 协议
	// 4.1. 先发送 AUTH
	_, err = fmt.Fprintf(remoteConn, "AUTH %s\n", authToken)
	if err != nil {
		fmt.Println("[client] send AUTH error:", err)
		return
	}

	remoteReader := bufio.NewReader(remoteConn)

	// 4.2. 等服务端返回 OK
	authResp, err := remoteReader.ReadString('\n')
	if err != nil {
		fmt.Println("[client] read AUTH response error:", err)
		return
	}

	authResp = strings.TrimSpace(authResp)

	if authResp != "OK" {
		fmt.Println("[client] auth failed:", authResp)
		return
	}

	_, err = fmt.Fprintf(remoteConn, "CONNECT %s\n", targetAddr)
	if err != nil {
		fmt.Println("[local] send CONNECT to remote error:", err)
		_ = socks5Reply(clientConn, 0x01)
		return
	}

	// remoteReader := bufio.NewReader(remoteConn)

	// 5. 等待远端返回 OK
	line, err := remoteReader.ReadString('\n')
	if err != nil {
		fmt.Println("[local] read remote response error:", err)
		_ = socks5Reply(clientConn, 0x01)
		return
	}

	if line != "OK\n" {
		fmt.Println("[local] remote connect failed:", line)
		_ = socks5Reply(clientConn, 0x05) // connection refused
		return
	}

	// 6. 回复浏览器：SOCKS5 CONNECT 成功
	if err := socks5Reply(clientConn, 0x00); err != nil {
		fmt.Println("[local] socks5 reply error:", err)
		return
	}

	// 7. 双向转发
	errCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(remoteConn, clientConn)
		closeWrite(remoteConn)
		errCh <- err
	}()

	go func() {
		// 注意：这里 remote -> client 方向要从 remoteReader 读。
		// 因为前面 ReadString 可能预读了一部分数据。
		_, err := io.Copy(clientConn, remoteReader)
		closeWrite(clientConn)
		errCh <- err
	}()

	<-errCh

	fmt.Println("[local] client closed:", clientAddr)
}

func socks5Handshake(conn net.Conn) error {
	header := make([]byte, 2)

	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	ver := header[0]
	nMethods := int(header[1])

	if ver != 0x05 {
		return errors.New("not SOCKS5")
	}

	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// 这里只支持 no authentication
	_, err := conn.Write([]byte{0x05, 0x00})
	return err
}

func socks5ReadRequest(conn net.Conn) (string, error) {
	header := make([]byte, 4)

	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}

	ver := header[0]
	cmd := header[1]
	// rsv := header[2]
	atyp := header[3]

	if ver != 0x05 {
		return "", errors.New("invalid SOCKS version")
	}

	if cmd != 0x01 {
		return "", errors.New("only TCP CONNECT is supported")
	}

	var host string

	switch atyp {
	case 0x01:
		// IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()

	case 0x03:
		// Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", err
		}

		hostLen := int(lenBuf[0])
		hostBuf := make([]byte, hostLen)

		if _, err := io.ReadFull(conn, hostBuf); err != nil {
			return "", err
		}

		host = string(hostBuf)

	case 0x04:
		// IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()

	default:
		return "", errors.New("unsupported address type")
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}

	port := binary.BigEndian.Uint16(portBuf)

	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func socks5Reply(conn net.Conn, rep byte) error {
	// SOCKS5 response:
	// VER REP RSV ATYP BND.ADDR BND.PORT
	//
	// 这里简化返回：
	// 05 REP 00 01 00 00 00 00 00 00
	_, err := conn.Write([]byte{
		0x05,
		rep,
		0x00,
		0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	})
	return err
}

func closeWrite(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
	}
}
