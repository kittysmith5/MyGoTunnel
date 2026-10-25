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
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{quicudp.ALPN},
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			snapshot := m.current.Load().Clone()
			snapshot.MinVersion = tls.VersionTLS13
			snapshot.NextProtos = []string{quicudp.ALPN}
			snapshot.SessionTicketsDisabled = true
			snapshot.WrapSession, snapshot.UnwrapSession = nil, nil
			return snapshot, nil
		},
	}
}

func handleQUICUDPTunnel(conn net.Conn, cfg *config.ServerConfig, logger *slog.Logger, permit *admission.Permit, limiter *authlimit.Limiter, resources *datagram.Resources) {
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
	if command != "UDP" || reader.Buffered() != 0 {
		logging.Failure(logger, "control", fmt.Errorf("invalid QUIC UDP command"))
		return
	}
	handleUDPTunnel(conn, reader, logger, started, 0, permit.Release, cfg.UDPQueueConfig, resources)
}
