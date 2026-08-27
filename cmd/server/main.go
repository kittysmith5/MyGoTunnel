package main

import (
	"bufio"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/logging"
	"mygotunnel/internal/relay"
	"mygotunnel/internal/tunnel"
)

func main() {
	configPath := flag.String("config", "configs/server.json", "config file path")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, or error")
	logFormat := flag.String("log-format", logging.FormatText, "log format: text or json")
	flag.Parse()

	logger, err := logging.New(os.Stderr, logging.Options{
		Component: "server",
		Level:     *logLevel,
		Format:    *logFormat,
	})
	if err != nil {
		slog.Error("invalid logging configuration", "component", "server", "error", err)
		os.Exit(2)
	}

	if err := run(*configPath, logger); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run(configPath string, logger *slog.Logger) error {
	cfg, err := config.LoadServerConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	}

	ln, err := tls.Listen("tcp", cfg.ListenAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.ListenAddr, err)
	}
	defer ln.Close()

	logger.Info("TLS listener started",
		"listen_addr", cfg.ListenAddr,
		"alpn", "http/1.1",
	)

	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.Error("accept connection failed", "error", err)
			continue
		}

		go handleTunnel(conn, cfg, logger)
	}
}

func handleTunnel(tunnelConn net.Conn, cfg *config.ServerConfig, logger *slog.Logger) {
	defer tunnelConn.Close()

	remoteAddr := tunnelConn.RemoteAddr().String()
	connectionLogger := logger.With("client_addr", remoteAddr)
	startedAt := time.Now()
	connectionLogger.Debug("connection accepted")
	defer func() {
		connectionLogger.Debug("connection closed", "duration", time.Since(startedAt))
	}()

	reader := bufio.NewReader(tunnelConn)

	if err := checkAuth(tunnelConn, reader, cfg.AuthToken); err != nil {
		connectionLogger.Warn("authentication failed", "error", err)
		return
	}

	line, err := tunnel.ReadLine(reader)
	if err != nil {
		connectionLogger.Warn("read CONNECT request failed", "error", err)
		return
	}

	if !strings.HasPrefix(line, "CONNECT ") {
		connectionLogger.Warn("invalid tunnel command")
		return
	}

	targetAddr := strings.TrimSpace(strings.TrimPrefix(line, "CONNECT "))
	if targetAddr == "" {
		connectionLogger.Warn("empty target address")
		return
	}

	requestLogger := connectionLogger.With("target_addr", targetAddr)
	requestLogger.Debug("CONNECT request received")

	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		requestLogger.Warn("dial target failed", "error", err)
		_ = tunnel.SendERR(tunnelConn)
		return
	}
	defer targetConn.Close()

	if err := tunnel.SendOK(tunnelConn); err != nil {
		requestLogger.Warn("send CONNECT response failed", "error", err)
		return
	}

	requestLogger.Info("tunnel established")
	result := relay.CopyBidirectional(tunnelConn, reader, targetConn, targetConn)
	logging.LogTunnelResult(requestLogger, result, startedAt)
}

func checkAuth(conn net.Conn, reader *bufio.Reader, expectedToken string) (authErr error) {
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf("set authentication deadline: %w", err)
	}
	defer func() {
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			authErr = errors.Join(authErr, fmt.Errorf("clear authentication deadline: %w", err))
		}
	}()

	line, err := tunnel.ReadLine(reader)
	if err != nil {
		return fmt.Errorf("read authentication request: %w", err)
	}

	if !strings.HasPrefix(line, "AUTH ") {
		return rejectAuth(conn, errors.New("invalid authentication command"))
	}

	clientToken := strings.TrimSpace(strings.TrimPrefix(line, "AUTH "))

	if subtle.ConstantTimeCompare([]byte(clientToken), []byte(expectedToken)) != 1 {
		return rejectAuth(conn, errors.New("authentication token mismatch"))
	}

	if err := tunnel.SendOK(conn); err != nil {
		return fmt.Errorf("send authentication response: %w", err)
	}

	return nil
}

func rejectAuth(conn net.Conn, reason error) error {
	if err := tunnel.SendERR(conn); err != nil {
		return errors.Join(reason, fmt.Errorf("send authentication rejection: %w", err))
	}

	return reason
}
