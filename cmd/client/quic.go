package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/preconnect"
	"mygotunnel/internal/quicudp"
	"mygotunnel/internal/tunnel"
)

func openRemoteQUICUDP(ctx context.Context, cfg *config.ClientConfig, resources *datagram.Resources, pools ...*preconnect.Pool) (session *remoteSession, err error) {
	session = &remoteSession{Stage: "quic"}
	defer func() {
		if errors.Is(err, quicudp.ErrAuthRejected) {
			err = errAuthRejected
		} else if errors.Is(err, quicudp.ErrLimit) {
			err = &tunnel.TargetError{Code: "LIMIT"}
		}
	}()
	if len(pools) > 0 && pools[0] != nil {
		pool := pools[0]
		session.Stage = "pool"
		started := time.Now()
		entry := pool.Take(ctx)
		session.PoolAcquireDuration = time.Since(started)
		if entry != nil {
			conn, ok := entry.Conn.(*quicudp.Conn)
			if !ok {
				closeUnusedRemote(entry.Conn)
				return session, fmt.Errorf("invalid QUIC prepared connection")
			}
			session.PoolHit = true
			interrupted := make(chan struct{})
			stop := context.AfterFunc(ctx, func() {
				_ = conn.Close()
				close(interrupted)
			})
			started = time.Now()
			response, exchangeErr := exchangePrepared(ctx, entry, "", true, session)
			session.ControlDuration = time.Since(started)
			if !stop() {
				<-interrupted
			}
			if ctx.Err() != nil {
				_ = conn.Close()
				return session, ctx.Err()
			}
			if exchangeErr == nil && response == "OK" {
				if entry.Reader.Buffered() != 0 {
					_ = conn.Close()
					return session, fmt.Errorf("unexpected UDP QUIC control payload")
				}
				if err = conn.SetDeadline(time.Time{}); err != nil {
					_ = conn.Close()
					return session, err
				}
				conn.EnableDatagrams()
				session.Conn, session.Reader = conn, entry.Reader
				return session, nil
			}
			_ = conn.Close()
			if exchangeErr == nil {
				return session, tunnel.ParseConnectResponse(response)
			}
			if ctx.Err() != nil {
				return session, ctx.Err()
			}
			if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
				return session, context.DeadlineExceeded
			}
			if !preparedTransportFailure(exchangeErr) {
				return session, exchangeErr
			}
			// Only retry an unused prepared transport. No business datagram has
			// been sent, and the fallback retains QUIC and the same trust policy.
			session.PoolHit = false
			session.PoolFallback = true
			pool.RecordFallback()
		}
	}
	session.Stage = "quic"
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
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
		close(interrupted)
	})
	defer func() {
		if !stop() {
			<-interrupted
			if err == nil {
				err = ctx.Err()
				session.Conn, session.Reader = nil, nil
			}
		}
	}()
	if err = conn.SetDeadline(controlDeadline(ctx)); err != nil {
		return session, err
	}
	session.Stage = "auth"
	started = time.Now()
	defer func() { session.ControlDuration += time.Since(started) }()
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
