package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/logging"
	"mygotunnel/internal/relay"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
	"mygotunnel/internal/utlsconn"
)

func main() {
	configPath := flag.String("config", "configs/client.json", "config file path")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, or error")
	logFormat := flag.String("log-format", logging.FormatText, "log format: text or json")
	flag.Parse()

	logger, err := logging.New(os.Stderr, logging.Options{
		Component: "client",
		Level:     *logLevel,
		Format:    *logFormat,
	})
	if err != nil {
		slog.Error("invalid logging configuration", "component", "client", "error", err)
		os.Exit(2)
	}

	if err := run(*configPath, logger); err != nil {
		logger.Error("client stopped", "error", err)
		os.Exit(1)
	}
}

func run(configPath string, logger *slog.Logger) error {
	cfg, err := config.LoadClientConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ln, err := net.Listen("tcp", cfg.LocalAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.LocalAddr, err)
	}
	defer ln.Close()

	logger.Info("SOCKS5 listener started",
		"listen_addr", cfg.LocalAddr,
		"remote_addr", cfg.RemoteAddr,
		"sni", cfg.SNI,
	)

	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.Error("accept connection failed", "error", err)
			continue
		}

		go handleClient(conn, cfg, logger)
	}
}

func handleClient(clientConn net.Conn, cfg *config.ClientConfig, logger *slog.Logger) {
	defer clientConn.Close()

	clientAddr := clientConn.RemoteAddr().String()
	connectionLogger := logger.With("client_addr", clientAddr)
	startedAt := time.Now()
	connectionLogger.Debug("connection accepted")
	defer func() {
		connectionLogger.Debug("connection closed", "duration", time.Since(startedAt))
	}()

	if err := socks5.Handshake(clientConn); err != nil {
		connectionLogger.Warn("SOCKS5 handshake failed", "error", err)
		return
	}

	targetAddr, err := socks5.ReadRequest(clientConn)
	if err != nil {
		connectionLogger.Warn("SOCKS5 request failed", "error", err)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}

	requestLogger := connectionLogger.With("target_addr", targetAddr)
	requestLogger.Debug("SOCKS5 CONNECT received")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	remoteConn, err := utlsconn.Dial(ctx, cfg.RemoteAddr, cfg.SNI)
	cancel()
	if err != nil {
		requestLogger.Warn("dial remote uTLS server failed",
			"remote_addr", cfg.RemoteAddr,
			"error", err,
		)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}
	defer remoteConn.Close()

	remoteReader := bufio.NewReader(remoteConn)

	if err := tunnel.SendAuth(remoteConn, cfg.AuthToken); err != nil {
		requestLogger.Warn("send authentication request failed", "error", err)
		return
	}

	authResp, err := tunnel.ReadLine(remoteReader)
	if err != nil {
		requestLogger.Warn("read authentication response failed", "error", err)
		return
	}

	if authResp != "OK" {
		requestLogger.Warn("remote authentication rejected")
		return
	}

	if err := tunnel.SendConnect(remoteConn, targetAddr); err != nil {
		requestLogger.Warn("send CONNECT request failed", "error", err)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}

	resp, err := tunnel.ReadLine(remoteReader)
	if err != nil {
		requestLogger.Warn("read CONNECT response failed", "error", err)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}

	if resp != "OK" {
		requestLogger.Warn("remote CONNECT rejected")
		_ = socks5.Reply(clientConn, 0x05)
		return
	}

	if err := socks5.Reply(clientConn, 0x00); err != nil {
		requestLogger.Warn("send SOCKS5 success reply failed", "error", err)
		return
	}

	requestLogger.Info("tunnel established", "remote_addr", cfg.RemoteAddr)
	result := relay.CopyBidirectional(clientConn, clientConn, remoteConn, remoteReader)
	logging.LogTunnelResult(requestLogger, result, startedAt)
}
