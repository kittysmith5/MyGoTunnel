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
	"mygotunnel/internal/ingress"
	"mygotunnel/internal/logging"
	"mygotunnel/internal/operations"
	"mygotunnel/internal/quicstream"
	"mygotunnel/internal/quicudp"
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
	trustMode := flag.String("trust-mode", "pin", "connection code trust mode for export: pin or ca")
	capabilities := flag.Bool("capabilities", false, "print supported operational capabilities and exit")
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
	if *capabilities {
		if _, err := fmt.Printf("{\"certificate_reload\":%q}\n", certificateReloadCapability); err != nil {
			os.Exit(1)
		}
		return
	}
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
			if *trustMode != "pin" {
				logger.Error("initialization requires pin trust mode")
				os.Exit(2)
			}
			code, err = config.InitializeServer(*configPath, *publicAddr, *listenAddr)
		} else {
			code, err = config.ExportServerWithTrust(*configPath, *publicAddr, *trustMode)
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
	var entrance *ingress.Server
	var gate admission.AcceptGate
	var httpsLimits config.HTTPSConfig
	if cfg.HTTPS.Enabled {
		httpsLimits, err = cfg.HTTPS.Effective(maxSetup, opts.maxConnections)
		if err != nil {
			return err
		}
		entrance, err = ingress.New(cfg.HTTPS.HTML(), httpsLimits.MaxConnections, httpsLimits.MaxPreAuthPerIP, httpsLimits.PreAuthRatePerIP, httpsLimits.PreAuthBurstPerIP)
		if err != nil {
			return err
		}
		defer entrance.Close()
		gate = entrance.Accept
		shutdownDone := make(chan struct{})
		stopHTTP := context.AfterFunc(ctx, func() {
			defer close(shutdownDone)
			drain, cancel := context.WithTimeout(context.Background(), grace)
			defer cancel()
			_ = entrance.Shutdown(drain)
		})
		defer func() {
			if stopHTTP() {
				close(shutdownDone)
			}
			<-shutdownDone
		}()
	}
	resources := datagram.NewResources(cfg.ProcessLimits())
	authLimiter := authlimit.New(4096, 5, time.Minute, time.Minute)
	defer resources.Close()

	certificates, err := newCertificateManager(configPath, cfg)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}

	tlsConfig := certificates.tlsConfig()

	ln, err := tls.Listen("tcp", cfg.ListenAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.ListenAddr, err)
	}
	defer ln.Close()
	var listener net.Listener = ln
	if cfg.UDPQUICListenAddr != "" {
		_, maxAge := cfg.QueueLimits()
		udpListener, err := quicudp.Listen(cfg.UDPQUICListenAddr, certificates.quicTLSConfig(), resources, maxAge, opts.maxConnections, maxSetup)
		if err != nil {
			return fmt.Errorf("listen for UDP QUIC: %w", err)
		}
		defer udpListener.Close()
		listener, err = admission.MergeListeners(ln, udpListener)
		if err != nil {
			return err
		}
		defer listener.Close()
	}
	if cfg.TCPQUICListenAddr != "" {
		streams, e := quicstream.Listen(cfg.TCPQUICListenAddr, certificates.quicTLSConfigProtocols([]string{quicstream.ALPN}), resources, opts.maxConnections, maxSetup)
		if e != nil {
			return fmt.Errorf("listen for TCP QUIC: %w", e)
		}
		defer streams.Shutdown(grace)
		listener, e = admission.MergeListeners(listener, streams)
		if e != nil {
			return e
		}
		defer listener.Close()
	}
	stopReload := watchCertificateReload(certificates, logger)
	defer stopReload()

	logger.Info("listening",
		"version", buildinfo.Current().Version,
		"commit", buildinfo.Current().Commit,
		"listen_addr", cfg.ListenAddr,
		"udp_quic_listen_addr", cfg.UDPQUICListenAddr, "tcp_quic_listen_addr", cfg.TCPQUICListenAddr,
		"alpn", "http/1.1",
		"timezone", "UTC",
		"max_connections", opts.maxConnections,
		"max_setup", maxSetup,
		"max_idle", opts.maxIdle,
		"https_entry", cfg.HTTPS.Enabled,
		"https_max_connections", httpsLimits.MaxConnections,
		"https_max_pre_auth_per_ip", httpsLimits.MaxPreAuthPerIP,
		"https_pre_auth_rate_per_ip", httpsLimits.PreAuthRatePerIP,
		"https_pre_auth_burst_per_ip", httpsLimits.PreAuthBurstPerIP,
	)

	idleSlots := make(chan struct{}, opts.maxIdle)
	metrics := &admission.Counters{}
	stopStats := logging.StartStats(logger, 30*time.Second, func() []any {
		attrs := append([]any{"auth_rate_limited", authLimiter.Limited(), "active_connections", metrics.Open.Load(), "max_connections", opts.maxConnections, "setup_connections", metrics.Setup.Load(), "max_setup", maxSetup, "idle_connections", len(idleSlots), "max_idle", opts.maxIdle, "rejected", metrics.Rejected.Load()}, logging.UDPResourceAttrs(resources)...)
		if entrance != nil {
			attrs = append(attrs, entrance.Metrics.Attrs()...)
		}
		return attrs
	})
	defer stopStats()
	return admission.ServeContext(ctx, grace, listener, maxSetup, opts.maxConnections, func(conn net.Conn, permit *admission.Permit) {
		poolOptions := &serverPoolOptions{idleSlots: idleSlots, resumeSetup: permit.TryAcquire, abortContext: permit.AbortContext(), entrance: entrance, releasePreAuth: permit.ReleasePreAuth, acceptedAt: permit.StartedAt()}
		if _, ok := conn.(*quicudp.Conn); ok {
			handleQUICUDPTunnelWithPool(conn, cfg, logger, permit, poolOptions, authLimiter, resources)
			return
		}
		if _, ok := conn.(*quicstream.Stream); ok {
			poolOptions.entrance = nil
		}
		handleTunnelContextWithLimiter(ctx, conn, cfg, logger, permit.Release, poolOptions, authLimiter, resources)
	}, nil, metrics, gate)
}

type serverPoolOptions struct {
	idleSlots      chan struct{}
	resumeSetup    func() bool
	abortContext   context.Context
	entrance       *ingress.Server
	releasePreAuth func()
	acceptedAt     time.Time
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

	var reader *bufio.Reader

	authStarted := time.Now()
	peerKey := authlimit.PeerKey(tunnelConn.RemoteAddr())
	tokenProvider := func() []string { return cfg.ActiveAuthTokens(time.Now()) }
	if poolOptions != nil && poolOptions.entrance != nil {
		var err error
		reader, err = poolOptions.entrance.Route(parent, tunnelConn, poolOptions.acceptedAt, releaseSetup, poolOptions.releasePreAuth, func(line string) error {
			return authenticateTokenLine(line, tokenProvider, authLimiter, peerKey)
		})
		if err != nil {
			// Public ingress failures are aggregated separately from proxy attempts.
			connectionLogger.Debug("ingress closed")
			return
		}
		if reader == nil {
			return
		}
	} else {
		reader = bufio.NewReader(tunnelConn)
		if err := checkAuthTokenProvider(tunnelConn, reader, tokenProvider, authLimiter, peerKey); err != nil {
			if errors.Is(err, authlimit.ErrLimited) {
				connectionLogger.Debug("authentication rate limited")
				return
			}
			logging.Failure(connectionLogger, "auth", err, "auth_duration", time.Since(authStarted), "setup_duration", time.Since(startedAt))
			return
		}
	}

	if stream, ok := tunnelConn.(*quicstream.Stream); ok {
		stream.MarkAuthenticated()
		if poolOptions != nil && poolOptions.releasePreAuth != nil {
			poolOptions.releasePreAuth()
		}
		connectionLogger = connectionLogger.With("tcp_tunnel_transport", "quic")
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

	prepared, ok := awaitPreparedCommand(tunnelConn, reader, line, releaseSetup, poolOptions, connectionLogger)
	if !ok {
		return
	}
	line, idleDuration, pooled, commandACK := prepared.line, prepared.idleDuration, prepared.pooled, prepared.commandACK
	if pooled {
		connectStarted = time.Now()
		connectDeadline = connectStarted.Add(tunnel.ControlTimeout)
		if err := tunnelConn.SetDeadline(connectDeadline); err != nil {
			logging.Failure(connectionLogger, "connect", err)
			return
		}
	}

	if line == "UDP" {
		if _, ok := tunnelConn.(*quicstream.Stream); ok {
			logging.Failure(connectionLogger, "connect", fmt.Errorf("UDP is not supported on TCP QUIC streams"))
			return
		}
		if commandACK {
			if err := acknowledgePrepared(tunnelConn, connectDeadline); err != nil {
				logging.Failure(connectionLogger, "ack", err)
				return
			}
		}
		handleUDPTunnel(tunnelConn, reader, connectionLogger.With(
			"udp_tunnel_transport", "tcp",
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
	abortContext := context.Background()
	if poolOptions != nil && poolOptions.abortContext != nil {
		abortContext = poolOptions.abortContext
	}
	result := relay.CopyBidirectionalObservedContext(abortContext, tunnelConn, reader, targetConn, targetConn, logging.FirstDataObserver(requestLogger))
	logging.LogTunnelResult(requestLogger, result, startedAt, "tunnel", "target")
}

type preparedCommand struct {
	line         string
	idleDuration time.Duration
	pooled       bool
	commandACK   bool
}

// awaitPreparedCommand applies the same authenticated idle and setup budgets to
// TCP and QUIC. It never starts a target or enables QUIC business datagrams.
func awaitPreparedCommand(conn net.Conn, reader *bufio.Reader, line string, releaseSetup func(), options *serverPoolOptions, logger *slog.Logger) (preparedCommand, bool) {
	result := preparedCommand{line: line, commandACK: line == "PREPARE ACK"}
	if line != "PREPARE" && !result.commandACK {
		return result, true
	}
	if options == nil || cap(options.idleSlots) == 0 {
		_ = tunnel.SendERR(conn)
		return result, false
	}
	select {
	case options.idleSlots <- struct{}{}:
	default:
		_ = tunnel.SendBusy(conn)
		rejectQUICPreparedLimit(conn)
		return result, false
	}
	idleHeld := true
	releaseIdle := func() {
		if idleHeld {
			<-options.idleSlots
			idleHeld = false
		}
	}
	defer releaseIdle()
	releaseSetup()
	if err := conn.SetDeadline(time.Now().Add(tunnel.PreparedIdleTimeout)); err != nil {
		logging.Failure(logger, "prepare", err)
		return result, false
	}
	idleStarted := time.Now()
	var readyErr error
	if result.commandACK {
		readyErr = tunnel.SendReadyWithAck(conn)
	} else {
		readyErr = tunnel.SendReady(conn)
	}
	if readyErr != nil {
		logging.Failure(logger, "prepare", readyErr)
		return result, false
	}
	var err error
	result.line, err = tunnel.ReadLine(reader)
	result.idleDuration = time.Since(idleStarted)
	releaseIdle()
	if err != nil {
		logger.Debug("idle closed", "error", err)
		return result, false
	}
	if options.resumeSetup == nil || !options.resumeSetup() {
		if err := tunnel.SendTargetResult(conn, syscall.ENOBUFS); err != nil {
			logging.Failure(logger, "reply", err)
		}
		rejectQUICPreparedLimit(conn)
		return result, false
	}
	result.pooled = true
	return result, true
}

func rejectQUICPreparedLimit(conn net.Conn) {
	if quicConn, ok := conn.(*quicudp.Conn); ok {
		quicConn.RejectLimit()
	}
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

	if err := authenticateTokenLine(line, tokenProvider, limiter, peerKey); err != nil {
		return rejectAuth(conn, err)
	}
	if err := tunnel.SendOK(conn); err != nil {
		return fmt.Errorf("send authentication response: %w", err)
	}
	return nil
}

// authenticateTokenLine does not write: HTTPS fallback must own the first byte
// of any rejection response. Both entrances share the same credential decision.
var errAuthenticationTokenMismatch = errors.New("authentication token mismatch")

func authenticateTokenLine(line string, tokenProvider func() []string, limiter *authlimit.Limiter, peerKey string) error {
	if !strings.HasPrefix(line, "AUTH ") {
		return errors.New("invalid authentication command")
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
			return err
		}
	}
	if matched != 1 {
		return errAuthenticationTokenMismatch
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
