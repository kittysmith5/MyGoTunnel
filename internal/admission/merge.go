package admission

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// MergeListeners takes ownership of the listeners on success. Each child is
// accepted independently, so a quiet or slow listener cannot block the others.
// All accepted connections pass through the same caller's admission limits.
func MergeListeners(listeners ...net.Listener) (net.Listener, error) {
	if len(listeners) == 0 {
		return nil, fmt.Errorf("at least one listener is required")
	}
	for _, listener := range listeners {
		if listener == nil {
			return nil, fmt.Errorf("nil listener")
		}
	}
	m := &mergedListener{
		listeners: append([]net.Listener(nil), listeners...),
		address:   listeners[0].Addr(),
		accepted:  make(chan net.Conn),
		done:      make(chan struct{}),
		stopped:   make(chan struct{}),
	}
	m.workers.Add(len(m.listeners))
	for _, listener := range m.listeners {
		go m.acceptChild(listener)
	}
	go m.shutdown()
	return m, nil
}

type mergedListener struct {
	listeners []net.Listener
	address   net.Addr
	accepted  chan net.Conn
	done      chan struct{}
	stopped   chan struct{}
	stopOnce  sync.Once
	workers   sync.WaitGroup
	err       error // Written before done closes; immutable afterwards.
	closeErr  error // Written before stopped closes; immutable afterwards.
}

func (m *mergedListener) acceptChild(listener net.Listener) {
	defer m.workers.Done()
	var delay time.Duration
	for {
		select {
		case <-m.done:
			return
		default:
		}
		conn, err := listener.Accept()
		if err != nil {
			if conn != nil {
				_ = conn.Close()
			}
			var temporary net.Error
			if errors.As(err, &temporary) && temporary.Temporary() {
				// Keep transient resource failures local to this child. The
				// other transport may still be able to accept connections.
				delay = nextAcceptDelay(delay)
				if !waitAcceptRetry(m.done, delay) {
					return
				}
				continue
			}
			// A child that closes independently is also fatal: otherwise the
			// merged listener would silently stop serving one transport.
			m.stop(err)
			return
		}
		if conn == nil {
			m.stop(fmt.Errorf("listener accepted a nil connection"))
			return
		}
		delay = 0
		select {
		case m.accepted <- conn:
		case <-m.done:
			_ = conn.Close()
			return
		}
	}
}

func (m *mergedListener) stop(err error) {
	m.stopOnce.Do(func() {
		m.err = err
		close(m.done)
	})
}

// shutdown runs separately from child workers: a worker can initiate shutdown
// without waiting for itself, while Close still joins every worker.
func (m *mergedListener) shutdown() {
	<-m.done
	for _, listener := range m.listeners {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			m.closeErr = errors.Join(m.closeErr, err)
		}
	}
	m.workers.Wait()
	close(m.stopped)
}

func (m *mergedListener) Accept() (net.Conn, error) {
	select {
	case <-m.done:
		return nil, m.err
	default:
	}
	select {
	case <-m.done:
		return nil, m.err
	case conn := <-m.accepted:
		// If shutdown raced the handoff, this connection was never exposed
		// to the caller and remains ours to close.
		select {
		case <-m.done:
			_ = conn.Close()
			return nil, m.err
		default:
			return conn, nil
		}
	}
}

// Close closes every child and joins all Accept workers. It does not close
// connections already returned by Accept, which belong to the caller.
func (m *mergedListener) Close() error {
	m.stop(net.ErrClosed)
	<-m.stopped
	return m.closeErr
}

func (m *mergedListener) Addr() net.Addr { return m.address }
