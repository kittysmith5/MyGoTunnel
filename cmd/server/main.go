package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"mygotunnel/internal/admission"
	"mygotunnel/internal/authlimit"
	"mygotunnel/internal/buildinfo"
	"mygotunnel/internal/config"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/diagnostics"
	"mygotunnel/internal/dialmetrics"
	"mygotunnel/internal/logging"
	"mygotunnel/internal/operations"
	"mygotunnel/internal/relay"
	"mygotunnel/internal/setupwatch"
	"mygotunnel/internal/tunnel"
)

func main() {
	version := flag.Bool("version", false, "print build identity JSON and exit")
	diagnose := flag.Bool("check-config", false, "validate configuration without starting service")
	health := flag.Bool("health", false, "run bounded operational health check and exit")
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
	metricsPath := flag.String("runtime-metrics", "", "optional exclusive private runtime JSONL output file")
	shutdownTimeout := flag.Duration("shutdown-timeout", 15*time.Second, "maximum active connection drain time on shutdown")
	flag.Parse()
	if *version {
		if buildinfo.Write(os.Stdout) != nil {
			os.Exit(1)
		}
		return
	}
	if *diagnose || *health {
		os.Exit(operations.Check("server", *configPath, *health))
	}

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
	stopMetrics, err := diagnostics.Start(*metricsPath)
	if err != nil {
		logger.Error("metrics failed", "error", err)
		os.Exit(1)
	}
	defer stopMetrics()
	ctx, stopSignal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignal()
	if err := runContext(ctx, *shutdownTimeout, *configPath, logger, *maxSetup, serverOptions{*maxConnections, *maxIdle}); err != nil {
		logger.Error("stopped", "error", err)
		stopMetrics()
		os.Exit(1)
	}
}

type serverOptions struct{ maxConnections, maxIdle int }

func run(configPath string, logger *slog.Logger, maxSetup int, options ...serverOptions) error {
	return runContext(context.Background(), 0, configPath, logger, maxSetup, options...)
}

func runContext(ctx context.Context, grace time.Duration, configPath string, logger *slog.Logger, maxSetup int, options ...serverOptions) error {
	if grace < 0 {
		return fmt.Errorf("shutdown-timeout must not be negative")
	}
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
	resources := datagram.NewResources(cfg.ProcessLimits())
	authLimiter := authlimit.New(4096, 5, time.Minute, time.Minute)
	defer resources.Close()

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}

	tlsConfig := serverTLSConfig(cert)

	ln, err := tls.Listen("tcp", cfg.ListenAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.ListenAddr, err)
	}
	defer ln.Close()

	logger.Info("listening",
		"version", buildinfo.Current().Version,
		"commit", buildinfo.Current().Commit,
		"listen_addr", cfg.ListenAddr,
		"alpn", "http/1.1",
		"timezone", "UTC",
		"max_connections", opts.maxConnections,
		"max_setup", maxSetup,
		"max_idle", opts.maxIdle,
	)

	idleSlots := make(chan struct{}, opts.maxIdle)
	metrics := &admission.Counters{}
	stopStats := logging.StartStats(logger, 30*time.Second, func() []any {
		return append([]any{"auth_rate_limited", authLimiter.Limited(), "active_connections", metrics.Open.Load(), "max_connections", opts.maxConnections, "setup_connections", metrics.Setup.Load(), "max_setup", maxSetup, "idle_connections", len(idleSlots), "max_idle", opts.maxIdle, "rejected", metrics.Rejected.Load()}, logging.UDPResourceAttrs(resources)...)
	})
	defer stopStats()
	return admission.ServeContext(ctx, grace, ln, maxSetup, opts.maxConnections, func(conn net.Conn, permit *admission.Permit) {
		handleTunnelContextWithLimiter(ctx, conn, cfg, logger, permit.Release, &serverPoolOptions{idleSlots: idleSlots, resumeSetup: permit.TryAcquire}, authLimiter, resources)
	}, nil, metrics)
}

type serverPoolOptions struct {
	idleSlots   chan struct{}
	resumeSetup func() bool
}

func handleTunnel(tunnelConn net.Conn, cfg *config.ServerConfig, logger *slog.Logger, releaseSetup func()) {
	handleTunnelWithPool(tunnelConn, cfg, logger, releaseSetup, nil)
}

func handleTunnelWithPool(tunnelConn net.Conn, cfg *config.ServerConfig, logger *slog.Logger, releaseSetup func(), poolOptions *serverPoolOptions) {
	handleTunnelContext(context.Background(), tunnelConn, cfg, logger, releaseSetup, poolOptions)
}

func handleTunnelContext(parent context.Context, tunnelConn net.Conn, cfg *config.ServerConfig, logger *slog.Logger, releaseSetup func(), poolOptions *serverPoolOptions, resources ...*datagram.Resources) {
	handleTunnelContextWithLimiter(parent, tunnelConn, cfg, logger, releaseSetup, poolOptions, nil, resources...)
}

func handleTunnelContextWithLimiter(parent context.Context, tunnelConn net.Conn, cfg *config.ServerConfig, logger *slog.Logger, releaseSetup func(), poolOptions *serverPoolOptions, authLimiter *authlimit.Limiter, resources ...*datagram.Resources) {
	defer tunnelConn.Close()

	remoteAddr := tunnelConn.RemoteAddr().String()
	connectionLogger := logging.Connection(logger, remoteAddr)
	startedAt := time.Now()
	connectionLogger.Debug("accepted")
	defer func() {
		connectionLogger.Debug("released", "duration", time.Since(startedAt))
	}()

	reader := bufio.NewReader(tunnelConn)

	authStarted := time.Now()
	peerKey := authlimit.PeerKey(tunnelConn.RemoteAddr())
	if err := checkAuthTokenProvider(tunnelConn, reader, func() []string { return cfg.ActiveAuthTokens(time.Now()) }, authLimiter, peerKey); err != nil {
		if errors.Is(err, authlimit.ErrLimited) {
			connectionLogger.Debug("authentication rate limited")
			return
		}
		logging.Failure(connectionLogger, "auth", err, "auth_duration", time.Since(authStarted), "setup_duration", time.Since(startedAt))
		return
	}

	authDuration := time.Since(authStarted)
	connectStarted := time.Now()
	connectDeadline := time.Now().Add(tunnel.ControlTimeout)
	if err := tunnelConn.SetDeadline(connectDeadline); err != nil {
		logging.Failure(connectionLogger, "connect", err)
		return
	}
	line, err := tunnel.ReadLine(reader)
	if err != nil {
		logging.Failure(connectionLogger, "connect", err, "wait_duration", time.Since(connectStarted), "auth_duration", authDuration, "setup_duration", time.Since(startedAt))
		return
	}

	var idleDuration time.Duration
	pooled := false
	commandACK := line == "PREPARE ACK"
	if line == "PREPARE" || commandACK {
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
			logging.Failure(connectionLogger, "prepare", err)
			return
		}
		idleStarted := time.Now()
		var readyErr error
		if commandACK {
			readyErr = tunnel.SendReadyWithAck(tunnelConn)
		} else {
			readyErr = tunnel.SendReady(tunnelConn)
		}
		if readyErr != nil {
			logging.Failure(connectionLogger, "prepare", readyErr)
			return
		}
		line, err = tunnel.ReadLine(reader)
		idleDuration = time.Since(idleStarted)
		releaseIdle()
		if err != nil {
			connectionLogger.Debug("idle closed", "error", err)
			return
		}
		if !poolOptions.resumeSetup() {
			if err := tunnel.SendTargetResult(tunnelConn, syscall.ENOBUFS); err != nil {
				logging.Failure(connectionLogger, "reply", err)
			}
			return
		}
		pooled = true
		connectStarted = time.Now()
		connectDeadline = connectStarted.Add(tunnel.ControlTimeout)
		if err := tunnelConn.SetDeadline(connectDeadline); err != nil {
			logging.Failure(connectionLogger, "connect", err)
			return
		}
	}

	if line == "UDP" {
		if commandACK {
			if err := acknowledgePrepared(tunnelConn, connectDeadline); err != nil {
				logging.Failure(connectionLogger, "ack", err)
				return
			}
		}
		handleUDPTunnel(tunnelConn, reader, connectionLogger.With(
			"pool_connection", pooled, "auth_duration", authDuration, "idle_duration", idleDuration,
			"wait_duration", time.Since(connectStarted)), startedAt, idleDuration, releaseSetup, cfg.UDPQueueConfig, resources...)
		return
	}

	if !strings.HasPrefix(line, "CONNECT ") {
		connectionLogger.Warn("failed", "stage", "connect", "close_reason", "protocol")
		return
	}

	targetAddr := strings.TrimSpace(strings.TrimPrefix(line, "CONNECT "))
	if targetAddr == "" {
		connectionLogger.Warn("failed", "stage", "connect", "close_reason", "empty")
		return
	}

	waitDuration := time.Since(connectStarted)
	requestLogger := connectionLogger.With("target_addr", targetAddr)
	requestLogger.Debug("connect")
	if commandACK {
		if err := acknowledgePrepared(tunnelConn, connectDeadline); err != nil {
			logging.Failure(requestLogger, "ack", err)
			return
		}
	}

	ctx, cancel := context.WithDeadline(parent, connectDeadline)
	watch := setupwatch.Start(tunnelConn, reader, cancel)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	targetStarted := time.Now()
	targetConn, dialTimings, err := dialmetrics.Dial(ctx, dialer, "tcp", targetAddr)
	if watchErr := watch.Stop(connectDeadline); watchErr != nil {
		if targetConn != nil {
			_ = targetConn.Close()
		}
		err = watchErr
	}
	targetDuration := time.Since(targetStarted)
	cancel()
	if err != nil {
		logging.Failure(requestLogger, "dial", err, "dns_duration", dialTimings.DNS, "target_tcp_duration", dialTimings.TCP, "target_dial_duration", targetDuration, "dns_retry_count", dialTimings.DNSRetries, "setup_duration", time.Since(startedAt)-idleDuration)
		if replyErr := tunnel.SendTargetResult(tunnelConn, err); replyErr != nil {
			logging.Failure(requestLogger, "reply", replyErr)
		}
		return
	}
	defer targetConn.Close()

	replyStarted := time.Now()
	if err := tunnel.SendTargetResult(tunnelConn, nil); err != nil {
		logging.Failure(requestLogger, "reply", err)
		return
	}

	if err := tunnelConn.SetDeadline(time.Time{}); err != nil {
		logging.Failure(requestLogger, "control", err)
		return
	}
	releaseSetup()
	requestLogger.Info("ready",
		"pool_connection", pooled,
		"auth_duration", authDuration,
		"idle_duration", idleDuration,
		"wait_duration", waitDuration,
		"dns_duration", dialTimings.DNS, "target_tcp_duration", dialTimings.TCP, "target_dial_duration", targetDuration, "dns_retry_count", dialTimings.DNSRetries,
		"reply_duration", time.Since(replyStarted),
		"connect_duration", time.Since(connectStarted),
		"setup_duration", time.Since(startedAt)-idleDuration)
	result := relay.CopyBidirectional(tunnelConn, reader, targetConn, targetConn)
	logging.LogTunnelResult(requestLogger, result, startedAt)
}

func acknowledgePrepared(conn net.Conn, controlDeadline time.Time) error {
	deadline := time.Now().Add(tunnel.PreparedAckTimeout)
	if controlDeadline.Before(deadline) {
		deadline = controlDeadline
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	if err := tunnel.SendAcknowledged(conn); err != nil {
		return err
	}
	return conn.SetWriteDeadline(controlDeadline)
}

func checkAuth(conn net.Conn, reader *bufio.Reader, expectedToken string) error {
	return checkAuthTokens(conn, reader, []string{expectedToken}, nil, "")
}

func checkAuthTokens(conn net.Conn, reader *bufio.Reader, expectedTokens []string, limiter *authlimit.Limiter, peerKey string) error {
	return checkAuthTokenProvider(conn, reader, func() []string { return expectedTokens }, limiter, peerKey)
}

func checkAuthTokenProvider(conn net.Conn, reader *bufio.Reader, tokenProvider func() []string, limiter *authlimit.Limiter, peerKey string) (authErr error) {
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
	expectedTokens := tokenProvider()

	clientToken := strings.TrimSpace(strings.TrimPrefix(line, "AUTH "))

	matched := 0
	actual := sha256.Sum256([]byte(clientToken))
	for _, token := range expectedTokens {
		expected := sha256.Sum256([]byte(token))
		matched |= subtle.ConstantTimeCompare(actual[:], expected[:])
	}
	if limiter != nil {
		if err := limiter.Authenticate(peerKey, matched == 1); errors.Is(err, authlimit.ErrLimited) {
			return rejectAuth(conn, err)
		}
	}
	if matched != 1 {
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

// serverTLSConfig hardens the existing TLS transport; it does not emulate OpenSSL.
func serverTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
		// TLS 1.3 suites and key exchange retain Go defaults (including hybrid KEM).
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
}
