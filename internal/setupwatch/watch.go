// Package setupwatch cancels setup after a hard ingress read failure while
// preserving FIN half-closes and any application bytes received ahead of setup.
package setupwatch

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Watch owns reader until Stop returns. It peeks into the reader's existing
// bounded buffer without consuming bytes. A full buffer ends monitoring: setup
// retains its own timeout and relay will subsequently detect transport errors.
type Watch struct {
	conn     net.Conn
	done     chan struct{}
	stopping atomic.Bool
	once     sync.Once
	err      error // published by closing done
	stopErr  error // published by once
}

// Start transfers exclusive ownership of reader until Stop. Only hard read
// errors cancel setup; EOF may be a valid upload half-close and does not cancel.
func Start(conn net.Conn, reader *bufio.Reader, cancel context.CancelFunc) *Watch {
	w := &Watch{conn: conn, done: make(chan struct{})}
	go func() {
		defer close(w.done)
		for reader.Buffered() < reader.Size() {
			if _, err := reader.Peek(reader.Buffered() + 1); err != nil {
				if errors.Is(err, io.EOF) {
					return
				}
				var network net.Error
				if w.stopping.Load() && errors.As(err, &network) && network.Timeout() {
					return // Stop deliberately interrupted the pending peek.
				}
				w.err = fmt.Errorf("setup ingress read: %w", err)
				if cancel != nil {
					cancel()
				}
				return
			}
		}
	}()
	return w
}

// Stop interrupts and waits for the reader owner, then restores its read
// deadline. Callers must check the result before replying or starting relay.
// If interrupting reads fails, close the transport so no watcher is leaked.
func (w *Watch) Stop(readDeadline time.Time) error {
	w.once.Do(func() {
		w.stopping.Store(true)
		select {
		case <-w.done:
		default:
			if err := w.conn.SetReadDeadline(time.Now()); err != nil {
				w.stopErr = fmt.Errorf("interrupt setup ingress read: %w", err)
				conn := w.conn
				if wrapped, ok := conn.(interface{ NetConn() net.Conn }); ok {
					conn = wrapped.NetConn()
				}
				if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					w.stopErr = errors.Join(w.stopErr, fmt.Errorf("close setup ingress: %w", err))
				}
			}
			<-w.done
		}
		if err := w.conn.SetReadDeadline(readDeadline); err != nil {
			w.stopErr = errors.Join(w.stopErr, fmt.Errorf("restore setup ingress deadline: %w", err))
		}
		w.stopErr = errors.Join(w.err, w.stopErr)
	})
	return w.stopErr
}
