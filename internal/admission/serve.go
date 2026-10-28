// Package admission bounds setup and accepted connections independently.
package admission

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Permit supports temporarily releasing setup capacity while an authenticated
// connection waits in the idle pool, then reacquiring before target dial.
type Permit struct {
	mu             sync.Mutex
	slots          chan struct{}
	held           bool
	metrics        *Counters
	abortCtx       context.Context
	preAuthRelease func()
	startedAt      time.Time
}

// ReleasePreAuth releases only the optional source-IP admission slot.
func (p *Permit) ReleasePreAuth() {
	if p.preAuthRelease != nil {
		p.preAuthRelease()
	}
}

func (p *Permit) StartedAt() time.Time { return p.startedAt }

// AcceptGate runs before global slots or TLS handshakes. Release must be idempotent.
type AcceptGate func(net.Conn) (release func(), allowed bool)

// AbortContext is canceled only when the connection's shutdown grace expires.
// Process cancellation initially stops setup/acceptance and allows relay drain.
func (p *Permit) AbortContext() context.Context {
	if p.abortCtx != nil {
		return p.abortCtx
	}
	return context.Background()
}

func (p *Permit) Release() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.held {
		<-p.slots
		p.held = false
		if p.metrics != nil {
			p.metrics.Setup.Add(-1)
		}
	}
}

func (p *Permit) TryAcquire() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.held {
		return true
	}
	select {
	case p.slots <- struct{}{}:
		p.held = true
		if p.metrics != nil {
			p.metrics.Setup.Add(1)
		}
		return true
	default:
		return false
	}
}

// Serve retains the simple handler API. An optional total limit includes active
// relays; zero means no total limit. Handlers own and must close their connection.
func Serve(listener net.Listener, maxSetup int, handler func(net.Conn, func()), onOverload func(), maxConnections ...int) error {
	total := 0
	if len(maxConnections) > 0 {
		total = maxConnections[0]
	}
	return ServeWithPermit(listener, maxSetup, total, func(c net.Conn, p *Permit) { handler(c, p.Release) }, onOverload)
}

type Counters struct{ Open, Setup, Rejected atomic.Int64 }

func nextAcceptDelay(delay time.Duration) time.Duration {
	if delay == 0 {
		return 5 * time.Millisecond
	}
	return min(delay*2, time.Second)
}

// A closed done channel interrupts resource-pressure backoff immediately.
func waitAcceptRetry(done <-chan struct{}, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-done:
		return false
	case <-timer.C:
		return true
	}
}

func ServeWithPermit(listener net.Listener, maxSetup, maxConnections int, handler func(net.Conn, *Permit), onOverload func()) error {
	return ServeWithMetrics(listener, maxSetup, maxConnections, handler, onOverload, nil)
}

func ServeWithMetrics(listener net.Listener, maxSetup, maxConnections int, handler func(net.Conn, *Permit), onOverload func(), metrics *Counters) error {
	return ServeContext(context.Background(), 0, listener, maxSetup, maxConnections, handler, onOverload, metrics)
}

// ServeContext stops accepting on cancellation, drains handlers, then closes
// remaining connections after grace. Handlers must exit when their socket closes.
func ServeContext(ctx context.Context, grace time.Duration, listener net.Listener, maxSetup, maxConnections int, handler func(net.Conn, *Permit), onOverload func(), metrics *Counters, gates ...AcceptGate) error {
	if len(gates) > 1 {
		return errors.New("at most one accept gate is supported")
	}
	if grace < 0 {
		return fmt.Errorf("shutdown timeout must not be negative")
	}
	abortCtx, abort := context.WithCancel(context.Background())
	defer abort()
	var handlers sync.WaitGroup
	var mu sync.Mutex
	active := make(map[net.Conn]struct{})
	listenerClosed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(listenerClosed)
		_ = listener.Close()
	})
	defer func() {
		if stop() {
			// An early cancellation check can beat the scheduled callback.
			// It still owns listener closure once cancellation was observed.
			if ctx.Err() != nil {
				_ = listener.Close()
			}
			return
		}
		<-listenerClosed
	}()
	defer func() {
		done := make(chan struct{})
		go func() { handlers.Wait(); close(done) }()
		timer := time.NewTimer(grace)
		defer timer.Stop()
		select {
		case <-done:
			return
		case <-timer.C:
		}
		abort() // Interrupt both relay endpoints, including an already half-closed flow.
		mu.Lock()
		remaining := make([]net.Conn, 0, len(active))
		for c := range active {
			remaining = append(remaining, c)
		}
		mu.Unlock()
		for _, c := range remaining {
			_ = c.SetDeadline(time.Now())
			if wrapped, ok := c.(interface{ NetConn() net.Conn }); ok {
				_ = wrapped.NetConn().Close()
			} else {
				_ = c.Close()
			}
		}
		<-done
	}()
	if maxSetup <= 0 {
		return fmt.Errorf("max-setup must be positive")
	}
	if maxConnections < 0 {
		return fmt.Errorf("max-connections must not be negative")
	}
	slots := make(chan struct{}, maxSetup)
	var connections chan struct{}
	if maxConnections > 0 {
		connections = make(chan struct{}, maxConnections)
	}
	reject := func(c net.Conn) {
		_ = c.Close()
		if metrics != nil {
			metrics.Rejected.Add(1)
		}
		if onOverload != nil {
			onOverload()
		}
	}
	var delay time.Duration
	for {
		if ctx.Err() != nil {
			return nil
		}
		c, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var temporary net.Error
			if errors.As(err, &temporary) && temporary.Temporary() {
				delay = nextAcceptDelay(delay)
				if !waitAcceptRetry(ctx.Done(), delay) {
					return nil
				}
				continue
			}
			return fmt.Errorf("accept connection: %w", err)
		}
		if ctx.Err() != nil {
			_ = c.Close()
			return nil
		}
		delay = 0
		startedAt := time.Now()
		var releasePreAuth func()
		if len(gates) != 0 && gates[0] != nil {
			var allowed bool
			releasePreAuth, allowed = gates[0](c)
			if !allowed {
				reject(c)
				continue
			}
		}
		if connections != nil {
			select {
			case connections <- struct{}{}:
			default:
				if releasePreAuth != nil {
					releasePreAuth()
				}
				reject(c)
				continue
			}
		}
		select {
		case slots <- struct{}{}:
			permit := &Permit{slots: slots, held: true, metrics: metrics, abortCtx: abortCtx, preAuthRelease: releasePreAuth, startedAt: startedAt}
			if metrics != nil {
				metrics.Open.Add(1)
				metrics.Setup.Add(1)
			}
			handlers.Add(1)
			mu.Lock()
			active[c] = struct{}{}
			mu.Unlock()
			go func() {
				defer handlers.Done()
				defer func() { mu.Lock(); delete(active, c); mu.Unlock() }()
				if metrics != nil {
					defer metrics.Open.Add(-1)
				}
				if connections != nil {
					defer func() { <-connections }()
				}
				defer permit.Release()
				defer permit.ReleasePreAuth()
				handler(c, permit)
			}()
		default:
			if releasePreAuth != nil {
				releasePreAuth()
			}
			if connections != nil {
				<-connections
			}
			reject(c)
		}
	}
}
