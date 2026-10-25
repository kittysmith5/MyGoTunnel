package preconnect

import (
	"bufio"
	"context"
	"errors"
	"io"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/quicudp"
	"mygotunnel/internal/tunnel"
)

// NewQUICPreparer prepares a single-use, authenticated control connection.
// Business datagrams remain disabled until the caller completes UDP setup.
// Unsupported QUIC servers only back off this pool; foreground callers retain
// their ordinary QUIC path and never fall back to a different transport.
func NewQUICPreparer(cfg *config.ClientConfig, resources *datagram.Resources) Factory {
	return func(ctx context.Context) (*Entry, error) {
		return prepareQUIC(ctx, cfg, resources)
	}
}

func prepareQUIC(ctx context.Context, cfg *config.ClientConfig, resources *datagram.Resources) (entry *Entry, err error) {
	tlsConfig, err := quicudp.ClientTLSConfig(cfg.UDPQUICRemote(), cfg.SNI, cfg.CertificateFingerprint)
	if err != nil {
		return nil, err
	}
	_, maxAge := cfg.QueueLimits()
	started := time.Now()
	conn, err := quicudp.Dial(ctx, cfg.UDPQUICRemote(), tlsConfig, resources, maxAge, quicudp.DialOptions{
		TokenCache: true, TokenTrustScope: cfg.EffectiveTrustMode() + ":" + cfg.CertificateFingerprint,
		SocketReserve: 1,
	})
	if err != nil {
		return nil, err
	}
	duration := time.Since(started)
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		closeUnused(conn)
		close(interrupted)
	})
	defer func() {
		// Join a cancellation callback before returning ownership to the pool.
		if !stop() {
			<-interrupted
			if err == nil {
				err = ctx.Err()
				entry = nil
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				err = ctx.Err()
			} else if errors.Is(err, quicudp.ErrAuthRejected) {
				err = tunnel.ErrAuthRejected
			} else if errors.Is(err, quicudp.ErrLimit) {
				err = ErrBusy
			}
			closeUnused(conn)
		}
	}()
	deadline := time.Now().Add(tunnel.ControlTimeout + tunnel.ControlReplyTimeout)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err = tunnel.SendPrepareWithAck(conn, cfg.AuthToken); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	response, err := tunnel.ReadLine(reader)
	if err != nil {
		return nil, err
	}
	if response != "OK" {
		return nil, tunnel.ErrAuthRejected
	}
	response, err = tunnel.ReadLine(reader)
	if err != nil {
		// A pre-PREPARE QUIC server closes normally after the unknown command.
		// Timeouts, cancellation and explicit authentication errors retain their
		// original classification rather than being hidden as unsupported.
		if errors.Is(err, io.EOF) {
			return nil, ErrUnsupported
		}
		return nil, err
	}
	if response == "BUSY" {
		return nil, ErrBusy
	}
	if response != tunnel.PreparedAckReady || reader.Buffered() != 0 {
		return nil, ErrUnsupported
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return &Entry{Conn: conn, Reader: reader, CommandACK: true, QUICDuration: duration}, nil
}
