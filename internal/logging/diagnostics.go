package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/tunnel"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var ids atomic.Uint64
var processPrefix = func() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Now().UTC().Format("150405.000")
	}
	return hex.EncodeToString(b[:])
}()

// IDs correlate events within one process; they are not shared over the wire.
func Connection(logger *slog.Logger, peer string) *slog.Logger {
	return logger.With("connection_id", processPrefix+"-"+fmtID(ids.Add(1)), "client_addr", peer)
}
func fmtID(n uint64) string {
	const digits = "0123456789abcdef"
	var b [16]byte
	i := len(b)
	for {
		i--
		b[i] = digits[n&15]
		n >>= 4
		if n == 0 {
			return string(b[i:])
		}
	}
}
func Reason(err error) string {
	if err == nil {
		return "eof"
	}
	var target *tunnel.TargetError
	if errors.As(err, &target) {
		return target.Reason()
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		if dns.IsNotFound {
			return "dns_not_found"
		}
		if dns.IsTimeout {
			return "dns_timeout"
		}
		if dns.IsTemporary {
			return "dns_temporary"
		}
		return "dns"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	var n net.Error
	if errors.As(err, &n) && n.Timeout() {
		return "timeout"
	}
	switch {
	case errors.Is(err, tunnel.ErrAuthRejected), errors.Is(err, tunnel.ErrConnectRejected):
		return "rejected"
	case errors.Is(err, tunnel.ErrControlLineTooLong), errors.Is(err, datagram.ErrResourceLimit),
		errors.Is(err, syscall.EMFILE), errors.Is(err, syscall.ENFILE), errors.Is(err, syscall.ENOBUFS), errors.Is(err, syscall.ENOMEM):
		return "limit"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "unreachable"
	case errors.Is(err, tunnel.ErrConnectResponse):
		return "protocol"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.EPIPE):
		return "pipe"
	case errors.Is(err, net.ErrClosed), errors.Is(err, syscall.ENOTCONN):
		return "closed"
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "truncated"
	default:
		return "error"
	}
}
func Failure(logger *slog.Logger, stage string, err error, attrs ...any) {
	if stage == "" {
		stage = "relay"
	}
	reason := Reason(err)
	fields := append([]any{"stage", stage, "close_reason", reason}, attrs...)
	// Keep unknown failures diagnosable even at INFO/WARN; recognized system
	// errors retain their complete chain in DEBUG only.
	if reason == "error" {
		fields = append(fields, "error", err)
	}
	logger.Warn("failed", fields...)
	if reason != "error" {
		fields = append(fields, "error", err)
	}
	logger.Debug("error", fields...)
}

// StartStats stops and joins its goroutine before returning from the stop call.
func StartStats(logger *slog.Logger, interval time.Duration, snapshot func() []any) func() {
	stop, done := make(chan struct{}), make(chan struct{})
	var once sync.Once
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				logger.Info("stats", snapshot()...)
			}
		}
	}()
	return func() { once.Do(func() { close(stop) }); <-done }
}
