package preconnect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync"
	"time"
)

type Factory func(context.Context) (*Entry, error)
type Options struct {
	Size     int
	IdleTTL  time.Duration
	RetryMin time.Duration
	RetryMax time.Duration
}

// Pool owns only unused, authenticated connections. Used connections never return.
type Pool struct {
	mu                sync.Mutex
	idle              []*Entry
	filling           int
	closed            bool
	unsupportedLogged bool
	nextRetry         time.Time
	retry             time.Duration
	opts              Options
	factory           Factory
	logger            *slog.Logger
	ctx               context.Context
	cancel            context.CancelFunc
	wake              chan struct{}
	wg                sync.WaitGroup
}

func New(opts Options, factory Factory, logger *slog.Logger) (*Pool, error) {
	if opts.Size < 1 || opts.Size > 32 || factory == nil {
		return nil, fmt.Errorf("pool size must be between 1 and 32 and factory must be provided")
	}
	if opts.IdleTTL == 0 {
		opts.IdleTTL = 45 * time.Second
	}
	if opts.RetryMin == 0 {
		opts.RetryMin = 500 * time.Millisecond
	}
	if opts.RetryMax == 0 {
		opts.RetryMax = 30 * time.Second
	}
	if opts.IdleTTL <= 0 || opts.RetryMin <= 0 || opts.RetryMax < opts.RetryMin {
		return nil, fmt.Errorf("invalid pool timing options")
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Pool{opts: opts, factory: factory, logger: logger, ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1)}
	p.wg.Add(1)
	go p.manage()
	return p, nil
}
func (p *Pool) signal() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}
func (p *Pool) manage() {
	defer p.wg.Done()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		p.mu.Lock()
		if !p.closed && p.ctx.Err() == nil && !time.Now().Before(p.nextRetry) {
			for len(p.idle)+p.filling < p.opts.Size {
				p.filling++
				p.wg.Add(1)
				go p.fill()
			}
		}
		p.mu.Unlock()
		select {
		case <-p.ctx.Done():
			return
		case <-p.wake:
		case <-ticker.C:
		}
	}
}
func (p *Pool) fill() {
	defer p.wg.Done()
	ctx, cancel := context.WithTimeout(p.ctx, 35*time.Second)
	entry, err := p.factory(ctx)
	cancel()
	if err == nil {
		if entry == nil || entry.Conn == nil || entry.Reader == nil {
			err = fmt.Errorf("invalid prepared connection")
		} else {
			err = entry.Conn.SetReadDeadline(time.Now().Add(p.opts.IdleTTL))
		}
	}
	p.mu.Lock()
	p.filling--
	if err != nil {
		logUnsupported := false
		if errors.Is(err, ErrUnsupported) {
			p.retry = p.opts.RetryMax
			logUnsupported = !p.unsupportedLogged
			p.unsupportedLogged = true
		} else {
			if p.retry == 0 {
				p.retry = p.opts.RetryMin
			} else {
				p.retry *= 2
			}
			if p.retry > p.opts.RetryMax {
				p.retry = p.opts.RetryMax
			}
		}
		p.nextRetry = time.Now().Add(p.retry + time.Duration(rand.Float64()*float64(p.retry)/4))
		p.mu.Unlock()
		if entry != nil && entry.Conn != nil {
			_ = entry.Conn.Close()
		}
		if p.logger != nil {
			p.logger.Debug("preconnection unavailable", "error", err)
		}
		if logUnsupported && p.logger != nil {
			p.logger.Info("preconnections unavailable; using direct connections with periodic probes")
		}
		return
	}
	if p.closed || p.ctx.Err() != nil {
		p.mu.Unlock()
		entry.Conn.Close()
		return
	}
	p.unsupportedLogged = false
	p.retry = 0
	p.nextRetry = time.Time{}
	entry.expires = time.Now().Add(p.opts.IdleTTL)
	entry.done = make(chan struct{})
	p.idle = append(p.idle, entry)
	p.wg.Add(1)
	go p.guard(entry)
	p.mu.Unlock()
}
func (p *Pool) guard(entry *Entry) {
	defer p.wg.Done()
	_, entry.guardErr = entry.Reader.Peek(1)
	close(entry.done)
	p.mu.Lock()
	owned := false
	for i, candidate := range p.idle {
		if candidate == entry {
			p.idle = append(p.idle[:i], p.idle[i+1:]...)
			owned = true
			break
		}
	}
	p.mu.Unlock()
	if owned {
		entry.Conn.Close()
		p.signal()
	}
}

// Take never waits for refill. Interrupt the passive EOF monitor and hand off
// reader ownership before allowing caller to write CONNECT or read its response.
func (p *Pool) Take(ctx context.Context) *Entry {
	for {
		if ctx.Err() != nil {
			return nil
		}
		p.mu.Lock()
		if p.closed || len(p.idle) == 0 {
			p.mu.Unlock()
			return nil
		}
		entry := p.idle[0]
		p.idle = p.idle[1:]
		p.mu.Unlock()
		p.signal()
		if !time.Now().Before(entry.expires) {
			entry.Conn.Close()
			continue
		}
		if err := entry.Conn.SetReadDeadline(time.Now()); err != nil {
			entry.Conn.Close()
			continue
		}
		select {
		case <-entry.done:
		case <-ctx.Done():
			entry.Conn.Close()
			return nil
		}
		var netErr net.Error
		if !errors.As(entry.guardErr, &netErr) || !netErr.Timeout() {
			entry.Conn.Close()
			continue
		}
		if err := entry.Conn.SetReadDeadline(time.Time{}); err != nil {
			entry.Conn.Close()
			continue
		}
		return entry
	}
}
func (p *Pool) closeIdle() {
	p.mu.Lock()
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()
	for _, entry := range idle {
		entry.Conn.Close()
	}
}
func (p *Pool) Close() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.cancel()
	p.closeIdle()
	p.wg.Wait()
}

// IdleCount is a snapshot of ready, unused connections, excluding ongoing fills.
func (p *Pool) IdleCount() int { p.mu.Lock(); defer p.mu.Unlock(); return len(p.idle) }
