package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
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
	AckDuration           time.Duration
	PoolHit, PoolFallback bool
	Stage                 string
}

func controlDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(tunnel.ControlTimeout + tunnel.ControlReplyTimeout)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		return parent
	}
	return deadline
}
func openRemote(ctx context.Context, cfg *config.ClientConfig, target string, pool *preconnect.Pool) (session *remoteSession, err error) {
	return openRemoteCommand(ctx, cfg, target, pool, false)
}

func openRemoteUDP(ctx context.Context, cfg *config.ClientConfig, pool *preconnect.Pool) (*remoteSession, error) {
	return openRemoteCommand(ctx, cfg, "", pool, true)
}

func openRemoteCommand(ctx context.Context, cfg *config.ClientConfig, target string, pool *preconnect.Pool, udp bool) (session *remoteSession, err error) {
	session = &remoteSession{Stage: "pool"}
	if pool != nil {
		start := time.Now()
		entry := pool.Take(ctx)
		session.PoolAcquireDuration = time.Since(start)
		if entry != nil {
			session.Stage = "connect"
			session.PoolHit = true
			stop := context.AfterFunc(ctx, func() { closeUnusedRemote(entry.Conn) })
			defer stop()
			start = time.Now()
			response, exchangeErr := exchangePrepared(ctx, entry, target, udp, session)
			err = exchangeErr
			session.ControlDuration = time.Since(start)
			stop()
			if err == nil && response == "OK" {
				session.Conn = entry.Conn
				session.Reader = entry.Reader
				session.PoolHit = true
				return session, nil
			}
			closeUnusedRemote(entry.Conn)
			if err == nil {
				return session, tunnel.ParseConnectResponse(response)
			}
			if ctx.Err() != nil {
				return session, ctx.Err()
			}
			// A socket deadline may fire before the context timer publishes Err.
			// Do not start a fallback with an already exhausted parent budget.
			if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
				return session, context.DeadlineExceeded
			}
			if !preparedTransportFailure(err) {
				return session, err
			}
			// Retry only transport failure on an unused prepared connection, before any
			// application payload has been sent. Never retry explicit target rejection.
			session.PoolHit = false
			session.PoolFallback = true
			pool.RecordFallback()
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
	if udp {
		err = tunnel.SendUDPSetup(conn, cfg.AuthToken)
	} else {
		err = tunnel.SendSetup(conn, cfg.AuthToken, target)
	}
	if err != nil {
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
	// The server starts its CONNECT budget after AUTH. Reserve final reply time
	// from the same phase boundary instead of consuming it during authentication.
	if err = conn.SetDeadline(controlDeadline(ctx)); err != nil {
		return session, err
	}
	session.Stage = "connect"
	response, err = tunnel.ReadLine(reader)
	if err != nil {
		return session, err
	}
	if err = tunnel.ParseConnectResponse(response); err != nil {
		return session, err
	}
	session.Conn = conn
	session.Reader = reader
	return session, nil
}

func exchangePrepared(ctx context.Context, entry *preconnect.Entry, target string, udp bool, session *remoteSession) (string, error) {
	deadline := controlDeadline(ctx)
	started := time.Now()
	ackComplete := false
	if entry.CommandACK {
		session.Stage = "ack"
		deadline = minTime(deadline, started.Add(tunnel.PreparedAckTimeout))
		defer func() {
			if !ackComplete {
				session.AckDuration = time.Since(started)
			}
		}()
	}
	if err := entry.Conn.SetDeadline(deadline); err != nil {
		return "", err
	}
	var err error
	if udp {
		err = tunnel.SendUDPAssociate(entry.Conn)
	} else {
		err = tunnel.SendConnect(entry.Conn, target)
	}
	if err != nil {
		return "", err
	}
	response, err := tunnel.ReadLine(entry.Reader)
	if err != nil || !entry.CommandACK {
		return response, err
	}
	if response != tunnel.CommandAcknowledged {
		// An explicit ERR must retain its code and never trigger a retry. OK is
		// invalid at this phase, rather than an implicit successful ACK.
		if response == "OK" {
			return "", tunnel.ErrConnectResponse
		}
		return response, nil
	}
	session.AckDuration = time.Since(started)
	ackComplete = true
	// Stop ACK timing here; target connection completion has its own budget.
	session.Stage = "connect"
	if err := entry.Conn.SetDeadline(controlDeadline(ctx)); err != nil {
		return "", err
	}
	return tunnel.ReadLine(entry.Reader)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func preparedTransportFailure(err error) bool {
	var network net.Error
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) || errors.As(err, &network)
}

// No application payload has been sent on a failed setup connection. Close the
// TCP transport directly so a TLS close notification cannot extend ACK timeout.
func closeUnusedRemote(conn net.Conn) {
	if wrapped, ok := conn.(interface{ NetConn() net.Conn }); ok {
		_ = wrapped.NetConn().Close()
	} else {
		_ = conn.Close()
	}
}
