package preconnect

import (
	"bufio"
	"context"
	"errors"
	"io"
	"mygotunnel/internal/config"
	"mygotunnel/internal/tunnel"
	"mygotunnel/internal/utlsconn"
	"net"
	"sync/atomic"
	"time"
)

var ErrUnsupported = errors.New("server does not support preconnections")
var ErrBusy = errors.New("server preconnection capacity reached")

var errAckUnsupported = errors.New("server does not support prepared command acknowledgments")

// Entry is single-use. Taking it transfers Conn and the SAME Reader to caller.
type Entry struct {
	Conn        net.Conn
	Reader      *bufio.Reader
	DialTimings utlsconn.DialTimings
	// QUICDuration is background dial/handshake time, not foreground setup time.
	QUICDuration time.Duration
	CommandACK   bool
	done         chan struct{}
	guardErr     error
	expires      time.Time
	refreshAt    time.Time
}

func Prepare(ctx context.Context, cfg *config.ClientConfig) (entry *Entry, err error) {
	return prepare(ctx, cfg, false)
}

// NewPreparer scopes capability discovery to one configured pool. Old servers
// get one legacy retry after authenticated unsupported negotiation; that result
// is cached for a bounded interval, allowing subsequent server upgrades.
func NewPreparer(cfg *config.ClientConfig) Factory {
	var legacyUntil atomic.Int64
	return func(ctx context.Context) (*Entry, error) {
		if time.Now().UnixNano() < legacyUntil.Load() {
			return Prepare(ctx, cfg)
		}
		entry, err := prepare(ctx, cfg, true)
		if errors.Is(err, errAckUnsupported) && ctx.Err() == nil {
			if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
				return nil, context.DeadlineExceeded
			}
			entry, err = Prepare(ctx, cfg)
		}
		// Only a successful legacy READY establishes a legacy capability cache.
		if err == nil && !entry.CommandACK {
			legacyUntil.Store(time.Now().Add(5 * time.Minute).UnixNano())
		}
		return entry, err
	}
}

func prepare(ctx context.Context, cfg *config.ClientConfig, ack bool) (entry *Entry, err error) {
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	conn, timings, err := utlsconn.DialWithOptions(dialCtx, cfg.RemoteAddr, cfg.SNI, cfg.CertificateFingerprint, utlsconn.Options{SessionCache: cfg.TLSSessionCache})
	cancel()
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { closeUnused(conn) })
	defer stop()
	defer func() {
		if err != nil {
			// Cancellation closes the socket to interrupt any setup I/O. That
			// close can surface before the next protocol read checks ctx.Err.
			if contextErr := ctx.Err(); contextErr != nil {
				err = contextErr
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
	reader := bufio.NewReader(conn)
	if ack {
		err = tunnel.SendPrepareWithAck(conn, cfg.AuthToken)
	} else {
		err = tunnel.SendPrepare(conn, cfg.AuthToken)
	}
	if err != nil {
		return nil, err
	}
	response, err := tunnel.ReadLine(reader)
	if err != nil {
		return nil, err
	}
	if response != "OK" {
		return nil, tunnel.ErrAuthRejected
	}
	response, err = tunnel.ReadLine(reader)
	if err != nil {
		// An old server closes after receiving its unknown PREPARE command.
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			return nil, err
		}
		if ack {
			if errors.Is(err, io.EOF) {
				return nil, errAckUnsupported
			}
			return nil, err
		}
		return nil, ErrUnsupported
	}
	if response == "BUSY" {
		return nil, ErrBusy
	}
	commandACK := ack && response == tunnel.PreparedAckReady
	if ack && response == "ERR" {
		return nil, errAckUnsupported
	}
	if response != "READY" && !commandACK {
		return nil, ErrUnsupported
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return &Entry{Conn: conn, Reader: reader, DialTimings: timings, CommandACK: commandACK}, nil
}

// Prepared connections have not carried application payload. Close the raw
// transport so TLS close_notify cannot delay cancellation, retirement or Take.
func closeUnused(conn net.Conn) {
	if conn == nil {
		return
	}
	if wrapped, ok := conn.(interface{ NetConn() net.Conn }); ok {
		conn = wrapped.NetConn()
	}
	_ = conn.Close()
}
