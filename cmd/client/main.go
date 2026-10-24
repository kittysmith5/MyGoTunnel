package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mygotunnel/internal/admission"
	"mygotunnel/internal/authlimit"
	"mygotunnel/internal/buildinfo"
	"mygotunnel/internal/config"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/diagnostics"
	"mygotunnel/internal/logging"
	"mygotunnel/internal/operations"
	"mygotunnel/internal/preconnect"
	"mygotunnel/internal/relay"
	"mygotunnel/internal/setupwatch"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
)

const (
	socks5Timeout      = 5 * time.Second
	remoteDialTimeout  = 15 * time.Second
	remoteSetupTimeout = remoteDialTimeout + tunnel.ControlTimeout + tunnel.ControlReplyTimeout + tunnel.PreparedAckTimeout
)

func main() {
	version := flag.Bool("version", false, "print build identity JSON and exit")
	diagnose := flag.Bool("check-config", false, "validate configuration without starting service")
	health := flag.Bool("health", false, "run bounded operational health check and exit")
	configPath := flag.String("config", "configs/client.json", "config file path")
	importCode := flag.Bool("import", false, "import connection code from stdin and exit")
	poolMax := flag.Int("pool-max", 16, "maximum adaptive preconnections, size must not exceed this; 0 fixes pool at pool-size")
	poolSize := flag.Int("pool-size", 4, "authenticated preconnections, 0 disables, maximum 32")
	poolIdleSize := flag.Int("pool-idle-size", 0, "optional idle pool floor, 1..pool-size; 0 keeps normal floor")
	poolIdleAfter := flag.Duration("pool-idle-after", 2*time.Minute, "no-demand interval before shrinking toward pool-idle-size")
	maxConnections := flag.Int("max-connections", 1024, "maximum accepted local connections")
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
		os.Exit(operations.Check("client", *configPath, *health))
	}

	logger, err := logging.New(os.Stderr, logging.Options{
		Component: "client",
		Level:     *logLevel,
		Format:    *logFormat,
	})
	if err != nil {
		slog.Error("invalid logging configuration", "component", "client", "error", err)
		os.Exit(2)
	}

	if *importCode {
		if err := config.ImportClient(os.Stdin, *configPath); err != nil {
			logger.Error("import failed", "error", err)
			os.Exit(1)
		}
		logger.Info("imported", "config_path", *configPath)
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
	if err := runContext(ctx, *shutdownTimeout, *configPath, logger, *maxSetup, clientOptions{poolSize: *poolSize, maxConnections: *maxConnections, poolMax: *poolMax, poolIdleSize: *poolIdleSize, poolIdleAfter: *poolIdleAfter}); err != nil {
		logger.Error("stopped", "error", err)
		stopMetrics()
		os.Exit(1)
	}
}

type clientOptions struct {
	poolSize, maxConnections, poolMax, poolIdleSize int
	poolIdleAfter                                   time.Duration
}

func run(configPath string, logger *slog.Logger, maxSetup int, options ...clientOptions) error {
	return runContext(context.Background(), 0, configPath, logger, maxSetup, options...)
}

func runContext(ctx context.Context, grace time.Duration, configPath string, logger *slog.Logger, maxSetup int, options ...clientOptions) error {
	if grace < 0 {
		return fmt.Errorf("shutdown-timeout must not be negative")
	}
	opts := clientOptions{poolSize: 4, maxConnections: 1024, poolMax: 16}
	if len(options) > 0 {
		opts = options[0]
	}
	if opts.poolSize < 0 || opts.poolSize > 32 || opts.maxConnections <= 0 || opts.poolMax < 0 || opts.poolMax > 32 || (opts.poolSize > 0 && opts.poolMax > 0 && opts.poolMax < opts.poolSize) {
		return fmt.Errorf("invalid pool or connection limits")
	}
	if maxSetup <= 0 {
		return fmt.Errorf("max-setup must be positive")
	}
	if opts.poolIdleSize < 0 || opts.poolIdleSize > opts.poolSize || opts.poolIdleAfter < 0 {
		return fmt.Errorf("invalid idle pool limits")
	}
	cfg, err := config.LoadClientConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	resources := datagram.NewResources(cfg.ProcessLimits())
	authLimiter := authlimit.New(4096, 5, time.Minute, time.Minute)
	defer resources.Close()

	ln, err := net.Listen("tcp", cfg.LocalAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.LocalAddr, err)
	}
	defer ln.Close()

	poolLimit := opts.poolMax
	if poolLimit == 0 {
		poolLimit = opts.poolSize
	}
	if opts.poolSize == 0 {
		poolLimit = 0
	}
	logger.Info("listening",
		"version", buildinfo.Current().Version,
		"commit", buildinfo.Current().Commit,
		"listen_addr", cfg.LocalAddr,
		"remote_addr", cfg.RemoteAddr,
		"sni", cfg.SNI,
		"trust_mode", cfg.EffectiveTrustMode(),
		"tls_session_cache", cfg.TLSSessionCache,
		"socks_auth", cfg.SOCKSAuth != nil || cfg.SocksUsername != "" || cfg.SocksPassword != "",
		"timezone", "UTC",
		"max_connections", opts.maxConnections,
		"max_setup", maxSetup,
		"max_idle", poolLimit,
		"pool_idle_size", opts.poolIdleSize,
	)

	var pool *preconnect.Pool
	if opts.poolSize > 0 {
		pool, err = preconnect.New(preconnect.Options{Size: opts.poolSize, MaxSize: opts.poolMax, IdleSize: opts.poolIdleSize, IdleAfter: opts.poolIdleAfter}, preconnect.NewPreparer(cfg), logger)
		if err != nil {
			return err
		}
		defer pool.Close()
		stopPool := context.AfterFunc(ctx, pool.Close)
		defer stopPool()
	}
	metrics := &admission.Counters{}
	stopStats := logging.StartStats(logger, 30*time.Second, func() []any {
		idle := 0
		var ps preconnect.Stats
		if pool != nil {
			ps = pool.Stats()
			idle = ps.Idle
		}
		return append([]any{"auth_rate_limited", authLimiter.Limited(), "active_connections", metrics.Open.Load(), "max_connections", opts.maxConnections, "setup_connections", metrics.Setup.Load(), "max_setup", maxSetup, "idle_connections", idle, "max_idle", ps.Max, "rejected", metrics.Rejected.Load(), "pool_hits", ps.Hits, "pool_misses", ps.Misses, "pool_fallbacks", ps.Fallbacks, "pool_hit_rate", ps.HitRate, "pool_target", ps.Target, "pool_filling", ps.Filling, "pool_renewed", ps.Renewed, "pool_retry", ps.Retry}, logging.UDPResourceAttrs(resources)...)
	})
	defer stopStats()
	return admission.ServeContext(ctx, grace, ln, maxSetup, opts.maxConnections, func(conn net.Conn, permit *admission.Permit) {
		handleClientWithResourcesAndAuthLimiter(ctx, conn, cfg, logger, permit.Release, pool, resources, authLimiter, permit.AbortContext())
	}, nil, metrics)
}

func handleClient(clientConn net.Conn, cfg *config.ClientConfig, logger *slog.Logger, releaseSetup func(), pools ...*preconnect.Pool) {
	handleClientContext(context.Background(), clientConn, cfg, logger, releaseSetup, pools...)
}

func handleClientContext(parent context.Context, clientConn net.Conn, cfg *config.ClientConfig, logger *slog.Logger, releaseSetup func(), pools ...*preconnect.Pool) {
	var pool *preconnect.Pool
	if len(pools) > 0 {
		pool = pools[0]
	}
	handleClientWithResources(parent, clientConn, cfg, logger, releaseSetup, pool, datagram.DefaultResources)
}

func handleClientWithResources(parent context.Context, clientConn net.Conn, cfg *config.ClientConfig, logger *slog.Logger, releaseSetup func(), pool *preconnect.Pool, resources *datagram.Resources) {
	handleClientWithResourcesAndAuthLimiter(parent, clientConn, cfg, logger, releaseSetup, pool, resources, nil)
}

func handleClientWithResourcesAndAuthLimiter(parent context.Context, clientConn net.Conn, cfg *config.ClientConfig, logger *slog.Logger, releaseSetup func(), pool *preconnect.Pool, resources *datagram.Resources, authLimiter *authlimit.Limiter, abortContexts ...context.Context) {
	defer clientConn.Close()

	clientAddr := clientConn.RemoteAddr().String()
	connectionLogger := logging.Connection(logger, clientAddr)
	startedAt := time.Now()
	connectionLogger.Debug("accepted")
	defer func() {
		connectionLogger.Debug("released", "duration", time.Since(startedAt))
	}()

	if err := clientConn.SetDeadline(time.Now().Add(socks5Timeout)); err != nil {
		logging.Failure(connectionLogger, "socks", err, "socks_duration", time.Since(startedAt), "setup_duration", time.Since(startedAt))
		return
	}
	credentialProvider := func() []*socks5.Credentials {
		var socksCredentials []*socks5.Credentials
		if credentials, enabled := cfg.SOCKSCredentialSet(time.Now()); enabled {
			for _, c := range credentials {
				socksCredentials = append(socksCredentials, &socks5.Credentials{Username: c.Username, Password: c.Password})
			}
		}
		return socksCredentials
	}
	handshakeTimings, err := socks5.HandshakeWithCredentialProvider(clientConn, credentialProvider, authLimiter)
	connectionLogger = connectionLogger.With(
		"socks_first_byte_duration", handshakeTimings.FirstByte,
		"socks_method_duration", handshakeTimings.Method,
		"socks_auth_duration", handshakeTimings.Auth)
	if err != nil {
		logging.Failure(connectionLogger, "socks", err, "socks_duration", time.Since(startedAt), "setup_duration", time.Since(startedAt))
		return
	}

	requestStarted := time.Now()
	request, err := socks5.ReadRequestDetails(clientConn)
	connectionLogger = connectionLogger.With("socks_request_duration", time.Since(requestStarted))
	if err != nil {
		logging.Failure(connectionLogger, "socks", err, "socks_duration", time.Since(startedAt), "setup_duration", time.Since(startedAt))
		_ = socks5.Reply(clientConn, socks5.ReplyCode(err))
		return
	}

	if request.Command == socks5.CommandUDPAssociate {
		if err := clientConn.SetDeadline(time.Now().Add(remoteSetupTimeout + socks5Timeout)); err != nil {
			logging.Failure(connectionLogger, "socks", err)
			return
		}
		handleUDPAssociate(parent, clientConn, request, cfg, connectionLogger, startedAt, releaseSetup, pool, resources)
		return
	}
	targetAddr := net.JoinHostPort(request.Address, fmt.Sprint(request.Port))

	requestLogger := connectionLogger.With("target_addr", targetAddr)
	requestLogger.Debug("connect")

	// Bound the eventual SOCKS5 reply while remote setup runs.
	setupDeadline := time.Now().Add(remoteSetupTimeout + socks5Timeout)
	if err := clientConn.SetDeadline(setupDeadline); err != nil {
		logging.Failure(requestLogger, "socks", err, "socks_duration", time.Since(startedAt), "setup_duration", time.Since(startedAt))
		return
	}
	socksDuration := time.Since(startedAt)
	ctx, cancel := context.WithTimeout(parent, remoteSetupTimeout)
	clientReader := bufio.NewReader(clientConn)
	watch := setupwatch.Start(clientConn, clientReader, cancel)
	session, err := openRemote(ctx, cfg, targetAddr, pool)
	if watchErr := watch.Stop(setupDeadline); watchErr != nil {
		if session.Conn != nil {
			closeUnusedRemote(session.Conn)
		}
		err = watchErr
	}
	cancel()
	if err != nil {
		logging.Failure(requestLogger, session.Stage, err, "pool_hit", session.PoolHit, "pool_fallback", session.PoolFallback, "socks_duration", socksDuration, "control_duration", session.ControlDuration, "pool_acquire_duration", session.PoolAcquireDuration, "pool_ack_duration", session.AckDuration, "tcp_duration", session.Dial.TCPDuration, "tls_duration", session.Dial.TLSDuration, "tls_resumed", session.Dial.TLSResumed, "setup_duration", time.Since(startedAt))
		code := socks5.ReplyCode(err)
		var typed *tunnel.TargetError
		if !errors.As(err, &typed) && errors.Is(err, errTargetRejected) {
			code = 5
		}
		_ = socks5.Reply(clientConn, code)
		return
	}
	remoteConn, remoteReader := session.Conn, session.Reader
	defer remoteConn.Close()

	if err := socks5.Reply(clientConn, 0x00); err != nil {
		logging.Failure(requestLogger, "reply", err)
		return
	}

	if err := remoteConn.SetDeadline(time.Time{}); err != nil {
		logging.Failure(requestLogger, "control", err)
		return
	}
	if err := clientConn.SetDeadline(time.Time{}); err != nil {
		logging.Failure(requestLogger, "socks", err, "socks_duration", time.Since(startedAt), "setup_duration", time.Since(startedAt))
		return
	}
	releaseSetup()
	requestLogger.Info("ready", "remote_addr", cfg.RemoteAddr,
		"socks_duration", socksDuration,
		"tcp_duration", session.Dial.TCPDuration,
		"tls_duration", session.Dial.TLSDuration, "tls_resumed", session.Dial.TLSResumed,
		"control_duration", session.ControlDuration,
		"pool_hit", session.PoolHit,
		"pool_fallback", session.PoolFallback,
		"pool_acquire_duration", session.PoolAcquireDuration,
		"pool_ack_duration", session.AckDuration,
		"setup_duration", time.Since(startedAt))
	abortContext := context.Background()
	if len(abortContexts) > 0 && abortContexts[0] != nil {
		abortContext = abortContexts[0]
	}
	result := relay.CopyBidirectionalContext(abortContext, clientConn, clientReader, remoteConn, remoteReader)
	logging.LogTunnelResult(requestLogger, result, startedAt, "application", "tunnel")
}
