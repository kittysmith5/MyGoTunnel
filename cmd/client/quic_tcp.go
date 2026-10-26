package main

import (
	"bufio"
	"context"
	"errors"
	"mygotunnel/internal/config"
	"mygotunnel/internal/quicstream"
	"mygotunnel/internal/tunnel"
	"time"
)

func openRemoteTCPStream(ctx context.Context, cfg *config.ClientConfig, target string, pool *quicstream.Pool) (session *remoteSession, err error) {
	session = &remoteSession{Stage: "quic_stream"}
	if pool == nil {
		return session, errors.New("QUIC TCP pool unavailable")
	}
	started := time.Now()
	conn, t, err := pool.Open(ctx)
	session.PoolAcquireDuration = time.Since(started)
	session.QUICDuration = t.Handshake
	session.StreamReused = t.Reused
	session.Dial.NodeDNSDuration = t.DNS
	if err != nil {
		if errors.Is(err, quicstream.ErrBusy) {
			err = &tunnel.TargetError{Code: "LIMIT"}
		}
		return session, err
	}
	defer func() {
		if err != nil {
			_ = conn.Close()
		}
	}()
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); close(interrupted) })
	defer func() {
		if !stop() {
			<-interrupted
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	session.Stage = "control"
	if err = conn.SetDeadline(controlDeadline(ctx)); err != nil {
		return session, err
	}
	started = time.Now()
	defer func() { session.ControlDuration = time.Since(started) }()
	if err = tunnel.SendSetup(conn, cfg.AuthToken, target); err != nil {
		return session, err
	}
	reader := bufio.NewReader(conn)
	session.Stage = "auth"
	line, e := tunnel.ReadLine(reader)
	if e != nil {
		return session, e
	}
	if line != "OK" {
		return session, errAuthRejected
	}
	if err = conn.SetDeadline(controlDeadline(ctx)); err != nil {
		return session, err
	}
	session.Stage = "connect"
	line, err = tunnel.ReadLine(reader)
	if err != nil {
		return session, err
	}
	if err = tunnel.ParseConnectResponse(line); err != nil {
		return session, err
	}
	session.Conn, session.Reader = conn, reader
	return session, nil
}
