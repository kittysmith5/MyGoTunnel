package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"mygotunnel/internal/admission"
	"mygotunnel/internal/authlimit"
	"mygotunnel/internal/config"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/logging"
	"mygotunnel/internal/quicudp"
	"mygotunnel/internal/tunnel"
)

// QUIC uses its own ALPN and TLS 1.3, with the same atomically published
// certificate snapshots as TCP. Tickets and application 0-RTT are disabled.
func (m *certificateManager) quicTLSConfig() *tls.Config {
	return m.quicTLSConfigProtocols(quicudp.Protocols())
}
func (m *certificateManager) quicTLSConfigProtocols(protocols []string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: protocols,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			snapshot := m.current.Load().Clone()
			snapshot.MinVersion = tls.VersionTLS13
			snapshot.NextProtos = protocols
			snapshot.SessionTicketsDisabled = true
			snapshot.WrapSession, snapshot.UnwrapSession = nil, nil
			return snapshot, nil
		},
	}
}

func handleQUICUDPTunnel(conn net.Conn, cfg *config.ServerConfig, logger *slog.Logger, permit *admission.Permit, limiter *authlimit.Limiter, resources *datagram.Resources) {
	handleQUICUDPTunnelWithPool(conn, cfg, logger, permit, nil, limiter, resources)
}

func handleQUICUDPTunnelWithPool(conn net.Conn, cfg *config.ServerConfig, logger *slog.Logger, permit *admission.Permit, poolOptions *serverPoolOptions, limiter *authlimit.Limiter, resources *datagram.Resources) {
	defer conn.Close()
	logger = logging.Connection(logger, conn.RemoteAddr().String()).With("udp_tunnel_transport", "quic")
	started := time.Now()
	reader := bufio.NewReader(conn)
	if err := checkAuthTokenProvider(conn, reader, func() []string { return cfg.ActiveAuthTokens(time.Now()) }, limiter, authlimit.PeerKey(conn.RemoteAddr())); err != nil {
		if errors.Is(err, errAuthenticationTokenMismatch) || errors.Is(err, authlimit.ErrLimited) {
			if quicConn, ok := conn.(*quicudp.Conn); ok {
				quicConn.RejectAuthentication()
			}
		}
		logging.Failure(logger, "auth", err, "auth_duration", time.Since(started))
		return
	}
	permit.ReleasePreAuth()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		logging.Failure(logger, "control", err)
		return
	}
	command, err := tunnel.ReadLine(reader)
	if err != nil {
		logging.Failure(logger, "control", err)
		return
	}
	if (command == "PREPARE" || command == "PREPARE ACK") && (poolOptions == nil || cap(poolOptions.idleSlots) == 0) {
		_ = tunnel.SendBusy(conn)
		rejectQUICPreparedLimit(conn)
		return
	}
	prepared, ok := awaitPreparedCommand(conn, reader, command, permit.Release, poolOptions, logger)
	if !ok {
		return
	}
	command = prepared.line
	if command != "UDP" || reader.Buffered() != 0 {
		logging.Failure(logger, "control", fmt.Errorf("invalid QUIC UDP command"))
		return
	}
	if prepared.pooled {
		deadline := time.Now().Add(tunnel.ControlTimeout)
		if err := conn.SetDeadline(deadline); err != nil {
			logging.Failure(logger, "control", err)
			return
		}
		if prepared.commandACK {
			if err := acknowledgePrepared(conn, deadline); err != nil {
				logging.Failure(logger, "ack", err)
				return
			}
		}
	}
	handleUDPTunnelWithDial(conn, reader, logger.With("pool_connection", prepared.pooled, "idle_duration", prepared.idleDuration), started, prepared.idleDuration, permit.Release, cfg.UDPQueueConfig, targetUDPDial(poolOptions), resources)
}
