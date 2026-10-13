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
		logger.Info("connection imported", "config_path", *configPath)
		return
	}
	if err := run(*configPath, logger, *maxSetup, clientOptions{*poolSize, *maxConnections}); err != nil {
		logger.Error("client stopped", "error", err)
		os.Exit(1)
	}
}

type clientOptions struct{ poolSize, maxConnections int }

func run(configPath string, logger *slog.Logger, maxSetup int, options ...clientOptions) error {
	opts := clientOptions{4, 1024}
	if len(options) > 0 {
		opts = options[0]
	}
	if opts.poolSize < 0 || opts.poolSize > 32 || opts.maxConnections <= 0 {
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

	logger.Info("SOCKS5 listener started",
		"listen_addr", cfg.LocalAddr,
		"remote_addr", cfg.RemoteAddr,
		"sni", cfg.SNI,
	)

	var pool *preconnect.Pool
	if opts.poolSize > 0 {
		pool, err = preconnect.New(preconnect.Options{Size: opts.poolSize}, func(ctx context.Context) (*preconnect.Entry, error) { return preconnect.Prepare(ctx, cfg) }, logger)
		if err != nil {
			return err
		}
		defer pool.Close()
	}
	return admission.Serve(ln, maxSetup, func(conn net.Conn, release func()) {
		handleClient(conn, cfg, logger, release, pool)
	}, func() {
		logger.Debug("connection limit reached", "max_setup", maxSetup, "max_connections", opts.maxConnections)
	}, opts.maxConnections)
}

func handleClient(clientConn net.Conn, cfg *config.ClientConfig, logger *slog.Logger, releaseSetup func(), pools ...*preconnect.Pool) {
	defer clientConn.Close()

	clientAddr := clientConn.RemoteAddr().String()
	connectionLogger := logger.With("client_addr", clientAddr)
	startedAt := time.Now()
	connectionLogger.Debug("connection accepted")
	defer func() {
		connectionLogger.Debug("connection closed", "duration", time.Since(startedAt))
	}()

	if err := clientConn.SetDeadline(time.Now().Add(socks5Timeout)); err != nil {
		connectionLogger.Warn("set SOCKS5 deadline failed", "error", err)
		return
	}
	if err := socks5.Handshake(clientConn); err != nil {
		connectionLogger.Warn("SOCKS5 handshake failed", "error", err)
		return
	}

	targetAddr, err := socks5.ReadRequest(clientConn)
	if err != nil {
		connectionLogger.Warn("SOCKS5 request failed", "error", err)
		_ = socks5.Reply(clientConn, socks5.ReplyCode(err))
		return
	}

	requestLogger := connectionLogger.With("target_addr", targetAddr)
	requestLogger.Debug("SOCKS5 CONNECT received")

	// Bound the eventual SOCKS5 reply while remote setup runs.
	if err := clientConn.SetDeadline(time.Now().Add(remoteDialTimeout + tunnel.ControlTimeout + socks5Timeout)); err != nil {
		requestLogger.Warn("set connection setup deadline failed", "error", err)
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
		requestLogger.Warn("remote setup failed", "pool_fallback", session.PoolFallback, "tcp_duration", session.Dial.TCPDuration, "tls_duration", session.Dial.TLSDuration, "error", err)
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
		requestLogger.Warn("send SOCKS5 success reply failed", "error", err)
		return
	}

	if err := remoteConn.SetDeadline(time.Time{}); err != nil {
		requestLogger.Warn("clear tunnel control deadline failed", "error", err)
		return
	}
	if err := clientConn.SetDeadline(time.Time{}); err != nil {
		requestLogger.Warn("clear SOCKS5 deadline failed", "error", err)
		return
	}
	releaseSetup()
	requestLogger.Info("tunnel established", "remote_addr", cfg.RemoteAddr,
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
