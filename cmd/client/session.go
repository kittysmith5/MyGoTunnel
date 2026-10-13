package main

import (
	"bufio"
	"context"
	"fmt"
	"mygotunnel/internal/config"
	"mygotunnel/internal/preconnect"
	"mygotunnel/internal/tunnel"
	"mygotunnel/internal/utlsconn"
	"net"
	"time"
)

var errTargetRejected = tunnel.ErrConnectRejected
var errAuthRejected = tunnel.ErrAuthRejected

type remoteSession struct {
	Conn                  net.Conn
	Reader                *bufio.Reader
	Dial                  utlsconn.DialTimings
	ControlDuration       time.Duration
	PoolAcquireDuration   time.Duration
	PoolHit, PoolFallback bool
	Stage                 string
}

func controlDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(tunnel.ControlTimeout)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		return parent
	}
	return deadline
}
func openRemote(ctx context.Context, cfg *config.ClientConfig, target string, pool *preconnect.Pool) (session *remoteSession, err error) {
	session = &remoteSession{Stage: "pool"}
	if pool != nil {
		start := time.Now()
		entry := pool.Take(ctx)
		session.PoolAcquireDuration = time.Since(start)
		if entry != nil {
			session.Stage = "connect"
			session.PoolHit = true
			stop := context.AfterFunc(ctx, func() { entry.Conn.Close() })
			defer stop()
			start = time.Now()
			err = entry.Conn.SetDeadline(controlDeadline(ctx))
			if err == nil {
				err = tunnel.SendConnect(entry.Conn, target)
			}
			var response string
			if err == nil {
				response, err = tunnel.ReadLine(entry.Reader)
			}
			session.ControlDuration = time.Since(start)
			stop()
			if err == nil && response == "OK" {
				session.Conn = entry.Conn
				session.Reader = entry.Reader
				session.PoolHit = true
				return session, nil
			}
			entry.Conn.Close()
			if err == nil {
				return session, errTargetRejected
			}
			if ctx.Err() != nil {
				return session, ctx.Err()
			}
			// Retry only transport failure on an unused prepared connection, before any
			// application payload has been sent. Never retry explicit target rejection.
			session.PoolHit = false
			session.PoolFallback = true
		}
	}
	dialCtx, cancel := context.WithTimeout(ctx, remoteDialTimeout)
	conn, timings, err := utlsconn.DialWithTimings(dialCtx, cfg.RemoteAddr, cfg.SNI, cfg.CertificateFingerprint)
	cancel()
	session.Dial = timings
	session.Stage = timings.Stage
	if err != nil {
		return session, fmt.Errorf("dial remote: %w", err)
	}
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	session.Stage = "control"
	if err = conn.SetDeadline(controlDeadline(ctx)); err != nil {
		return session, err
	}
	session.Stage = "auth"
	start := time.Now()
	defer func() { session.ControlDuration += time.Since(start) }()
	if err = tunnel.SendSetup(conn, cfg.AuthToken, target); err != nil {
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
	response, err = tunnel.ReadLine(reader)
	if err != nil {
		return session, err
	}
	if response != "OK" {
		return session, errTargetRejected
	}
	session.Conn = conn
	session.Reader = reader
	return session, nil
}
