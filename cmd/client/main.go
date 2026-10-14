package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"mygotunnel/internal/admission"
	"mygotunnel/internal/config"
	"mygotunnel/internal/logging"
	"mygotunnel/internal/preconnect"
	"mygotunnel/internal/relay"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
)

const (
	socks5Timeout     = 5 * time.Second
	remoteDialTimeout = 15 * time.Second
)

func main() {
	configPath := flag.String("config", "configs/client.json", "config file path")
	importCode := flag.Bool("import", false, "import connection code from stdin and exit")
	poolMax := flag.Int("pool-max", 16, "maximum adaptive preconnections, size must not exceed this; 0 fixes pool at pool-size")
	poolSize := flag.Int("pool-size", 4, "authenticated preconnections, 0 disables, maximum 32")
	maxConnections := flag.Int("max-connections", 1024, "maximum accepted local connections")
	maxSetup := flag.Int("max-setup", 128, "maximum concurrent connection setups; established tunnels do not count")
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

	if *importCode {
		if err := config.ImportClient(os.Stdin, *configPath); err != nil {
			logger.Error("import failed", "error", err)
			os.Exit(1)
		}
		logger.Info("imported", "config_path", *configPath)
		return
	}
	if err := run(*configPath, logger, *maxSetup, clientOptions{*poolSize, *maxConnections, *poolMax}); err != nil {
		logger.Error("stopped", "error", err)
		os.Exit(1)
	}
}

type clientOptions struct{ poolSize, maxConnections, poolMax int }

func run(configPath string, logger *slog.Logger, maxSetup int, options ...clientOptions) error {
	opts := clientOptions{4, 1024, 16}
	if len(options) > 0 {
		opts = options[0]
	}
	if opts.poolSize < 0 || opts.poolSize > 32 || opts.maxConnections <= 0 || opts.poolMax < 0 || opts.poolMax > 32 || (opts.poolSize > 0 && opts.poolMax > 0 && opts.poolMax < opts.poolSize) {
		return fmt.Errorf("invalid pool or connection limits")
	}
	if maxSetup <= 0 {
		return fmt.Errorf("max-setup must be positive")
	}
	cfg, err := config.LoadClientConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

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
		"listen_addr", cfg.LocalAddr,
		"remote_addr", cfg.RemoteAddr,
		"sni", cfg.SNI,
		"socks_auth", cfg.SOCKSAuth != nil,
		"timezone", "UTC",
		"max_connections", opts.maxConnections,
		"max_setup", maxSetup,
		"max_idle", poolLimit,
	)

	var pool *preconnect.Pool
	if opts.poolSize > 0 {
		pool, err = preconnect.New(preconnect.Options{Size: opts.poolSize, MaxSize: opts.poolMax}, func(ctx context.Context) (*preconnect.Entry, error) { return preconnect.Prepare(ctx, cfg) }, logger)
		if err != nil {
			return err
		}
		defer pool.Close()
	}
	metrics := &admission.Counters{}
	stopStats := logging.StartStats(logger, 30*time.Second, func() []any {
		idle := 0
		var ps preconnect.Stats
		if pool != nil {
			ps = pool.Stats()
			idle = ps.Idle
		}
		return []any{"active_connections", metrics.Open.Load(), "max_connections", opts.maxConnections, "setup_connections", metrics.Setup.Load(), "max_setup", maxSetup, "idle_connections", idle, "max_idle", ps.Max, "rejected", metrics.Rejected.Load(), "pool_hits", ps.Hits, "pool_misses", ps.Misses, "pool_fallbacks", ps.Fallbacks, "pool_hit_rate", ps.HitRate, "pool_target", ps.Target, "pool_filling", ps.Filling}
	})
	defer stopStats()
	return admission.ServeWithMetrics(ln, maxSetup, opts.maxConnections, func(conn net.Conn, permit *admission.Permit) { handleClient(conn, cfg, logger, permit.Release, pool) }, nil, metrics)
}

func handleClient(clientConn net.Conn, cfg *config.ClientConfig, logger *slog.Logger, releaseSetup func(), pools ...*preconnect.Pool) {
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
	var socksAuth *socks5.Credentials
	if cfg.SOCKSAuth != nil {
		socksAuth = &socks5.Credentials{Username: cfg.SOCKSAuth.Username, Password: cfg.SOCKSAuth.Password}
	}
	if err := socks5.HandshakeWithAuth(clientConn, socksAuth); err != nil {
		logging.Failure(connectionLogger, "socks", err, "socks_duration", time.Since(startedAt), "setup_duration", time.Since(startedAt))
		return
	}

	targetAddr, err := socks5.ReadRequest(clientConn)
	if err != nil {
		logging.Failure(connectionLogger, "socks", err, "socks_duration", time.Since(startedAt), "setup_duration", time.Since(startedAt))
		_ = socks5.Reply(clientConn, socks5.ReplyCode(err))
		return
	}

	requestLogger := connectionLogger.With("target_addr", targetAddr)
	requestLogger.Debug("connect")

	// Bound the eventual SOCKS5 reply while remote setup runs.
	if err := clientConn.SetDeadline(time.Now().Add(remoteDialTimeout + tunnel.ControlTimeout + socks5Timeout)); err != nil {
		logging.Failure(requestLogger, "socks", err, "socks_duration", time.Since(startedAt), "setup_duration", time.Since(startedAt))
		return
	}
	socksDuration := time.Since(startedAt)
	var pool *preconnect.Pool
	if len(pools) > 0 {
		pool = pools[0]
	}
	ctx, cancel := context.WithTimeout(context.Background(), remoteDialTimeout+tunnel.ControlTimeout)
	session, err := openRemote(ctx, cfg, targetAddr, pool)
	cancel()
	if err != nil {
		logging.Failure(requestLogger, session.Stage, err, "pool_hit", session.PoolHit, "pool_fallback", session.PoolFallback, "socks_duration", socksDuration, "control_duration", session.ControlDuration, "pool_acquire_duration", session.PoolAcquireDuration, "tcp_duration", session.Dial.TCPDuration, "tls_duration", session.Dial.TLSDuration, "setup_duration", time.Since(startedAt))
		code := byte(1)
		if errors.Is(err, errTargetRejected) {
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
		"tls_duration", session.Dial.TLSDuration,
		"control_duration", session.ControlDuration,
		"pool_hit", session.PoolHit,
		"pool_fallback", session.PoolFallback,
		"pool_acquire_duration", session.PoolAcquireDuration,
		"setup_duration", time.Since(startedAt))
	result := relay.CopyBidirectional(clientConn, clientConn, remoteConn, remoteReader)
	logging.LogTunnelResult(requestLogger, result, startedAt)
}
