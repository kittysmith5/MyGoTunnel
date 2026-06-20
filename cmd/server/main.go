package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/relay"
	"mygotunnel/internal/tunnel"

	"github.com/quic-go/quic-go"
)

const nextProto = "mygotunnel-quic"

func buildQUICConfig(cfg config.QUICConfig) *quic.Config {
	quicConfig := &quic.Config{
		KeepAlivePeriod:    time.Duration(cfg.KeepAlivePeriodSeconds) * time.Second,
		MaxIdleTimeout:     time.Duration(cfg.MaxIdleTimeoutSeconds) * time.Second,
		MaxIncomingStreams: cfg.MaxIncomingStreams,
	}

	if cfg.InitialStreamReceiveWindow > 0 {
		quicConfig.InitialStreamReceiveWindow = cfg.InitialStreamReceiveWindow
	}
	if cfg.MaxStreamReceiveWindow > 0 {
		quicConfig.MaxStreamReceiveWindow = cfg.MaxStreamReceiveWindow
	}
	if cfg.InitialConnectionReceiveWindow > 0 {
		quicConfig.InitialConnectionReceiveWindow = cfg.InitialConnectionReceiveWindow
	}
	if cfg.MaxConnectionReceiveWindow > 0 {
		quicConfig.MaxConnectionReceiveWindow = cfg.MaxConnectionReceiveWindow
	}

	return quicConfig
}

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
		NextProtos:   []string{nextProto},
	}

	ln, err := quic.ListenAddr(cfg.ListenAddr, tlsConfig, buildQUICConfig(cfg.QUICConfig))
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	fmt.Println("[server] QUIC listening on", cfg.ListenAddr)

	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			fmt.Println("[server] accept error:", err)
			continue
		}

		go handleConnection(conn, cfg)
	}
}

func handleConnection(conn *quic.Conn, cfg *config.ServerConfig) {
	remoteAddr := conn.RemoteAddr().String()
	fmt.Println("[server] QUIC connected:", remoteAddr)

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			if !isNormalQUICClose(err) {
				fmt.Println("[server] accept stream error:", err)
			}
			return
		}

		go handleTunnel(stream, remoteAddr, cfg)
	}
}

func isNormalQUICClose(err error) bool {
	var appErr *quic.ApplicationError
	return errors.As(err, &appErr) && appErr.Remote && appErr.ErrorCode == 0
}

func handleTunnel(tunnelStream *quic.Stream, remoteAddr string, cfg *config.ServerConfig) {
	defer tunnelStream.Close()

	fmt.Println("[server] tunnel stream connected:", remoteAddr)

	reader := bufio.NewReader(tunnelStream)

	if !checkAuth(tunnelStream, reader, cfg.AuthToken) {
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
		_ = tunnel.SendERR(tunnelStream)
		return
	}
	defer targetConn.Close()

	if err := tunnel.SendOK(tunnelStream); err != nil {
		fmt.Println("[server] send OK error:", err)
		return
	}

	relay.CopyBidirectional(tunnelStream, reader, targetConn, targetConn)

	fmt.Println("[server] tunnel closed:", remoteAddr)
}

type readDeadlineSetter interface {
	SetReadDeadline(time.Time) error
}

func checkAuth(w io.Writer, reader *bufio.Reader, expectedToken string) bool {
	if ds, ok := w.(readDeadlineSetter); ok {
		_ = ds.SetReadDeadline(time.Now().Add(5 * time.Second))
		defer ds.SetReadDeadline(time.Time{})
	}

	line, err := tunnel.ReadLine(reader)
	if err != nil {
		return false
	}

	if !strings.HasPrefix(line, "AUTH ") {
		_ = tunnel.SendERR(w)
		return false
	}

	clientToken := strings.TrimSpace(strings.TrimPrefix(line, "AUTH "))

	if subtle.ConstantTimeCompare([]byte(clientToken), []byte(expectedToken)) != 1 {
		_ = tunnel.SendERR(w)
		return false
	}

	_ = tunnel.SendOK(w)
	return true
}
