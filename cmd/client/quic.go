package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/quicudp"
	"mygotunnel/internal/tunnel"
)

func openRemoteQUICUDP(ctx context.Context, cfg *config.ClientConfig, resources *datagram.Resources) (session *remoteSession, err error) {
	session = &remoteSession{Stage: "quic"}
	defer func() {
		if errors.Is(err, quicudp.ErrAuthRejected) {
			err = errAuthRejected
		}
	}()
	tlsConfig, err := quicudp.ClientTLSConfig(cfg.UDPQUICRemote(), cfg.SNI, cfg.CertificateFingerprint)
	if err != nil {
		return session, err
	}
	_, maxAge := cfg.QueueLimits()
	dialCtx, cancel := context.WithTimeout(ctx, remoteDialTimeout)
	started := time.Now()
	conn, err := quicudp.Dial(dialCtx, cfg.UDPQUICRemote(), tlsConfig, resources, maxAge, quicudp.DialOptions{
		TokenCache: true, TokenTrustScope: cfg.EffectiveTrustMode() + ":" + cfg.CertificateFingerprint,
	})
	cancel()
	session.QUICDuration = time.Since(started)
	if err != nil {
		return session, fmt.Errorf("dial UDP QUIC remote: %w", err)
	}
	defer func() {
		if err != nil {
			_ = conn.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err = conn.SetDeadline(controlDeadline(ctx)); err != nil {
		return session, err
	}
	session.Stage = "auth"
	started = time.Now()
	defer func() { session.ControlDuration = time.Since(started) }()
	if err = tunnel.SendUDPSetup(conn, cfg.AuthToken); err != nil {
		return session, err
	}
	reader := bufio.NewReader(conn)
	response, err := tunnel.ReadLine(reader)
	if err != nil {
		return session, err
	}
	if response != "OK" {
		return session, errAuthRejected
	}
	session.Stage = "connect"
	if err = conn.SetDeadline(controlDeadline(ctx)); err != nil {
		return session, err
	}
	response, err = tunnel.ReadLine(reader)
	if err != nil {
		return session, err
	}
	if err = tunnel.ParseConnectResponse(response); err != nil {
		return session, err
	}
	if reader.Buffered() != 0 {
		return session, fmt.Errorf("unexpected UDP QUIC control payload")
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return session, err
	}
	conn.EnableDatagrams()
	session.Conn, session.Reader = conn, reader
	return session, nil
}
