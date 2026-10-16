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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/logging"
	"mygotunnel/internal/relay"
	"mygotunnel/internal/socks5"
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
		if line == "UDP" {
			handleUDPTunnel(tunnelConn, reader, connectionLogger, startedAt)
			return
		}
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

const (
	udpTargetLimit       = 256
	udpTargetIdleTimeout = 2 * time.Minute
	udpTargetSweepPeriod = 15 * time.Second
	udpFrameQueueSize    = 256
)

type udpTarget struct {
	conn         *net.UDPConn
	destination  socks5.UDPDatagram
	lastActivity atomic.Int64
}

func handleUDPTunnel(tunnelConn net.Conn, reader *bufio.Reader, logger *slog.Logger, startedAt time.Time) {
	if err := tunnel.SendOK(tunnelConn); err != nil {
		logger.Warn("send UDP response failed", "error", err)
		return
	}
	done := make(chan struct{})
	var stopOnce sync.Once
	stop := func() { stopOnce.Do(func() { close(done) }) }
	requests := make(chan []byte, udpFrameQueueSize)
	responses := make(chan []byte, udpFrameQueueSize)
	targets := make(map[string]*udpTarget)
	var downloaded atomic.Uint64
	var droppedResponses atomic.Uint64
	var uploaded uint64
	var expiredTargets uint64
	peakTargets := 0
	defer func() {
		stop()
		for _, target := range targets {
			_ = target.conn.Close()
		}
		logger.Info("UDP tunnel closed",
			"upload_datagrams", uploaded,
			"download_datagrams", downloaded.Load(),
			"dropped_responses", droppedResponses.Load(),
			"expired_targets", expiredTargets,
			"peak_targets", peakTargets,
			"duration", time.Since(startedAt),
		)
	}()

	go func() {
		for {
			packet, err := tunnel.ReadDatagram(reader)
			if err != nil {
				stop()
				return
			}
			select {
			case requests <- packet:
			case <-done:
				return
			}
		}
	}()
	go func() {
		writer := bufio.NewWriterSize(tunnelConn, 32*1024)
		for {
			select {
			case packet := <-responses:
				if err := tunnel.WriteQueuedDatagrams(writer, packet, responses); err != nil {
					logger.Debug("write tunneled UDP response failed", "error", err)
					stop()
					_ = tunnelConn.Close()
					return
				}
			case <-done:
				return
			}
		}
	}()
	ticker := time.NewTicker(udpTargetSweepPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case frame := <-requests:
			destination, payload, err := socks5.ParseUDPDatagram(frame)
			if err != nil {
				logger.Debug("drop invalid tunneled UDP packet", "error", err)
				continue
			}
			address := net.JoinHostPort(destination.Host, strconv.Itoa(int(destination.Port)))
			target := targets[address]
			if target == nil {
				if len(targets) >= udpTargetLimit {
					logger.Debug("UDP session destination limit reached")
					continue
				}
				udpAddr, err := net.ResolveUDPAddr("udp", address)
				if err != nil {
					continue
				}
				conn, err := net.DialUDP("udp", nil, udpAddr)
				if err != nil {
					continue
				}
				target = &udpTarget{conn: conn, destination: destination}
				target.lastActivity.Store(time.Now().UnixNano())
				targets[address] = target
				if len(targets) > peakTargets {
					peakTargets = len(targets)
				}
				go readUDPResponses(target, responses, done, &downloaded, &droppedResponses, logger)
			}
			if _, err := target.conn.Write(payload); err != nil {
				logger.Debug("write target UDP failed", "error", err)
				continue
			}
			target.lastActivity.Store(time.Now().UnixNano())
			uploaded++
		case now := <-ticker.C:
			for address, target := range targets {
				last := time.Unix(0, target.lastActivity.Load())
				if now.Sub(last) >= udpTargetIdleTimeout {
					_ = target.conn.Close()
					delete(targets, address)
					expiredTargets++
				}
			}
		}
	}
}

func readUDPResponses(target *udpTarget, responses chan<- []byte, done <-chan struct{}, downloaded, dropped *atomic.Uint64, logger *slog.Logger) {
	buffer := make([]byte, tunnel.MaxDatagramSize)
	for {
		n, err := target.conn.Read(buffer)
		if err != nil {
			return
		}
		target.lastActivity.Store(time.Now().UnixNano())
		packet := socks5.BuildUDPDatagram(target.destination, buffer[:n])
		if len(packet) > tunnel.MaxDatagramSize {
			dropped.Add(1)
			continue
		}
		select {
		case responses <- packet:
			downloaded.Add(1)
		case <-done:
			return
		default:
			dropped.Add(1)
			logger.Debug("drop UDP response because tunnel queue is full")
		}
	}
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
