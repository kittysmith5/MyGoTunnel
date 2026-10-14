package preconnect

import (
	"bufio"
	"context"
	"errors"
	"mygotunnel/internal/config"
	"mygotunnel/internal/tunnel"
	"mygotunnel/internal/utlsconn"
	"net"
	"time"
)

var ErrUnsupported = errors.New("server does not support preconnections")
var ErrBusy = errors.New("server preconnection capacity reached")

// Entry is single-use. Taking it transfers Conn and the SAME Reader to caller.
type Entry struct {
	Conn        net.Conn
	Reader      *bufio.Reader
	DialTimings utlsconn.DialTimings
	done        chan struct{}
	guardErr    error
	expires     time.Time
	refreshAt   time.Time
}

func Prepare(ctx context.Context, cfg *config.ClientConfig) (entry *Entry, err error) {
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	conn, timings, err := utlsconn.DialWithTimings(dialCtx, cfg.RemoteAddr, cfg.SNI, cfg.CertificateFingerprint)
	cancel()
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	defer func() {
		if err != nil {
			_ = conn.Close()
		}
	}()
	deadline := time.Now().Add(tunnel.ControlTimeout)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	if err = tunnel.SendPrepare(conn, cfg.AuthToken); err != nil {
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
		return nil, ErrUnsupported
	}
	if response == "BUSY" {
		return nil, ErrBusy
	}
	if response != "READY" {
		return nil, ErrUnsupported
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return &Entry{Conn: conn, Reader: reader, DialTimings: timings}, nil
}
