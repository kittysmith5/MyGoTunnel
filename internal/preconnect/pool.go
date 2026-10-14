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
	MaxSize  int // zero keeps a fixed-size pool
	IdleTTL  time.Duration
	RetryMin time.Duration
	RetryMax time.Duration
}

// Pool owns only unused, authenticated connections. Used connections never return.
type Pool struct {
	mu                      sync.Mutex
	target                  int
	hits, misses, fallbacks uint64
	lastDemand              time.Time
	lastShrink              time.Time
	idle                    []*Entry
	filling                 int
	closed                  bool
	unsupportedLogged       bool
	nextRetry               time.Time
	retry                   time.Duration
	opts                    Options
	factory                 Factory
	logger                  *slog.Logger
	ctx                     context.Context
	cancel                  context.CancelFunc
	wake                    chan struct{}
	wg                      sync.WaitGroup
}

func New(opts Options, factory Factory, logger *slog.Logger) (*Pool, error) {
	if opts.Size < 1 || opts.Size > 32 || factory == nil {
		return nil, fmt.Errorf("pool size must be between 1 and 32 and factory must be provided")
	}
	if opts.MaxSize == 0 {
		opts.MaxSize = opts.Size
	}
	if opts.MaxSize < opts.Size || opts.MaxSize > 32 {
		return nil, fmt.Errorf("pool max must be between size and 32")
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
	p := &Pool{target: opts.Size, lastShrink: time.Now(), opts: opts, factory: factory, logger: logger, ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1)}
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
		now := time.Now()
		p.shrinkLocked(now)
		if !p.closed && p.ctx.Err() == nil && !now.Before(p.nextRetry) {
			for len(p.idle)+p.filling < p.target {
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
			p.logger.Debug("pool miss", "error", err)
		}
		if logUnsupported && p.logger != nil {
			p.logger.Info("pool unsupported; retrying")
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
	hit := false
	defer func() {
		p.mu.Lock()
		if hit {
			p.hits++
		} else {
			p.misses++
		}
		p.mu.Unlock()
	}()
	p.mu.Lock()
	if ctx.Err() == nil && !p.closed {
		p.lastDemand = time.Now()
		// Grow only when demand exhausts ready capacity; never exceed MaxSize.
		if len(p.idle) <= 1 && p.target < p.opts.MaxSize {
			p.target++
		}
	}
	p.mu.Unlock()
	p.signal()
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
		hit = true
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

// Stats is a consistent snapshot. Hits mean successful pool acquisition, not
// successful target connection. Fallbacks count subsequent transport failures.
type Stats struct {
	Hits, Misses, Fallbacks    uint64
	Idle, Filling, Target, Max int
	HitRate                    float64
}

func (p *Pool) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := Stats{Hits: p.hits, Misses: p.misses, Fallbacks: p.fallbacks, Idle: len(p.idle), Filling: p.filling, Target: p.target, Max: p.opts.MaxSize}
	if n := s.Hits + s.Misses; n > 0 {
		s.HitRate = 100 * float64(s.Hits) / float64(n)
	}
	return s
}
func (p *Pool) RecordFallback() { p.mu.Lock(); p.fallbacks++; p.mu.Unlock() }

func (p *Pool) shrinkLocked(now time.Time) {
	if p.target > p.opts.Size && now.Sub(p.lastDemand) >= 30*time.Second && now.Sub(p.lastShrink) >= 30*time.Second {
		p.target--
		p.lastShrink = now
	}
}
