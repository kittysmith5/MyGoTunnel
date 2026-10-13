package main

import (
	"bufio"
	"context"
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

	"mygotunnel/internal/admission"
	"mygotunnel/internal/config"
	"mygotunnel/internal/logging"
	"mygotunnel/internal/relay"
	"mygotunnel/internal/tunnel"
)

func main() {
	configPath := flag.String("config", "configs/server.json", "config file path")
	initialize := flag.Bool("init", false, "generate config, token and certificate, output connection code and exit")
	exportCode := flag.Bool("export", false, "output connection code for existing config and exit")
	publicAddr := flag.String("public-addr", "", "client reachable host:port for connection code")
	listenAddr := flag.String("listen", ":9001", "listen address for initialization")
	maxConnections := flag.Int("max-connections", 1024, "maximum accepted connections including idle and active tunnels")
	maxIdle := flag.Int("max-idle", 64, "maximum authenticated preconnections; zero disables preconnection support")
	maxSetup := flag.Int("max-setup", 128, "maximum concurrent connection setups; established tunnels do not count")
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

	if *initialize || *exportCode {
		if *initialize && *exportCode {
			logger.Error("choose either init or export")
			os.Exit(2)
		}
		var code string
		var err error
		if *initialize {
			code, err = config.InitializeServer(*configPath, *publicAddr, *listenAddr)
		} else {
			code, err = config.ExportServer(*configPath, *publicAddr)
		}
		if err != nil {
			logger.Error("connection setup failed", "error", err)
			os.Exit(1)
		}
		// Explicit credential export goes to stdout, never to the runtime logger.
		if _, err := fmt.Fprintln(os.Stdout, code); err != nil {
			logger.Error("write connection code failed", "error", err)
			os.Exit(1)
		}
		return
	}
	if err := run(*configPath, logger, *maxSetup, serverOptions{*maxConnections, *maxIdle}); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

type serverOptions struct{ maxConnections, maxIdle int }

func run(configPath string, logger *slog.Logger, maxSetup int, options ...serverOptions) error {
	opts := serverOptions{1024, 64}
	if len(options) > 0 {
		opts = options[0]
	}
	if opts.maxConnections <= 0 || opts.maxIdle < 0 {
		return fmt.Errorf("invalid connection limits")
	}
	if maxSetup <= 0 {
		return fmt.Errorf("max-setup must be positive")
	}
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

	idleSlots := make(chan struct{}, opts.maxIdle)
	return admission.ServeWithPermit(ln, maxSetup, opts.maxConnections, func(conn net.Conn, permit *admission.Permit) {
		handleTunnelWithPool(conn, cfg, logger, permit.Release, &serverPoolOptions{idleSlots: idleSlots, resumeSetup: permit.TryAcquire})
	}, func() {
		logger.Debug("connection limit reached", "max_setup", maxSetup, "max_connections", opts.maxConnections)
	})
}

type serverPoolOptions struct {
	idleSlots   chan struct{}
	resumeSetup func() bool
}

func handleTunnel(tunnelConn net.Conn, cfg *config.ServerConfig, logger *slog.Logger, releaseSetup func()) {
	handleTunnelWithPool(tunnelConn, cfg, logger, releaseSetup, nil)
}

func handleTunnelWithPool(tunnelConn net.Conn, cfg *config.ServerConfig, logger *slog.Logger, releaseSetup func(), poolOptions *serverPoolOptions) {
	defer tunnelConn.Close()

	remoteAddr := tunnelConn.RemoteAddr().String()
	connectionLogger := logger.With("client_addr", remoteAddr)
	startedAt := time.Now()
	connectionLogger.Debug("connection accepted")
	defer func() {
		connectionLogger.Debug("connection closed", "duration", time.Since(startedAt))
	}()

	reader := bufio.NewReader(tunnelConn)

	authStarted := time.Now()
	if err := checkAuth(tunnelConn, reader, cfg.AuthToken); err != nil {
		connectionLogger.Warn("authentication failed", "error", err)
		return
	}

	authDuration := time.Since(authStarted)
	connectStarted := time.Now()
	connectDeadline := time.Now().Add(tunnel.ControlTimeout)
	if err := tunnelConn.SetDeadline(connectDeadline); err != nil {
		connectionLogger.Warn("set CONNECT deadline failed", "error", err)
		return
	}
	line, err := tunnel.ReadLine(reader)
	if err != nil {
		connectionLogger.Warn("read CONNECT request failed", "error", err)
		return
	}

	pooled := false
	if line == "PREPARE" {
		if poolOptions == nil || cap(poolOptions.idleSlots) == 0 {
			_ = tunnel.SendERR(tunnelConn)
			return
		}
		select {
		case poolOptions.idleSlots <- struct{}{}:
		default:
			_ = tunnel.SendBusy(tunnelConn)
			return
		}
		idleHeld := true
		releaseIdle := func() {
			if idleHeld {
				<-poolOptions.idleSlots
				idleHeld = false
			}
		}
		defer releaseIdle()
		releaseSetup()
		if err := tunnelConn.SetDeadline(time.Now().Add(tunnel.PreparedIdleTimeout)); err != nil {
			return
		}
		if err := tunnel.SendReady(tunnelConn); err != nil {
			return
		}
		line, err = tunnel.ReadLine(reader)
		releaseIdle()
		if err != nil {
			connectionLogger.Debug("prepared connection closed", "error", err)
			return
		}
		if !poolOptions.resumeSetup() {
			_ = tunnel.SendERR(tunnelConn)
			return
		}
		pooled = true
		connectStarted = time.Now()
		connectDeadline = connectStarted.Add(tunnel.ControlTimeout)
		if err := tunnelConn.SetDeadline(connectDeadline); err != nil {
			return
		}
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

	ctx, cancel := context.WithDeadline(context.Background(), connectDeadline)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	targetStarted := time.Now()
	targetConn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	targetDuration := time.Since(targetStarted)
	cancel()
	if err != nil {
		requestLogger.Warn("dial target failed", "target_dial_duration", targetDuration, "error", err)
		_ = tunnel.SendERR(tunnelConn)
		return
	}
	defer targetConn.Close()

	if err := tunnel.SendOK(tunnelConn); err != nil {
		requestLogger.Warn("send CONNECT response failed", "error", err)
		return
	}

	if err := tunnelConn.SetDeadline(time.Time{}); err != nil {
		requestLogger.Warn("clear CONNECT deadline failed", "error", err)
		return
	}
	releaseSetup()
	requestLogger.Info("tunnel established",
		"pool_connection", pooled,
		"auth_duration", authDuration,
		"target_dial_duration", targetDuration,
		"connect_duration", time.Since(connectStarted),
		"setup_duration", time.Since(startedAt))
	result := relay.CopyBidirectional(tunnelConn, reader, targetConn, targetConn)
	logging.LogTunnelResult(requestLogger, result, startedAt)
}

func checkAuth(conn net.Conn, reader *bufio.Reader, expectedToken string) (authErr error) {
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf("set authentication deadline: %w", err)
	}
	defer func() {
		if err := conn.SetDeadline(time.Time{}); err != nil {
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
