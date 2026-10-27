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
	Size         int
	MaxSize      int // zero keeps a fixed-size pool
	IdleTTL      time.Duration
	IdleSize     int // zero preserves Size as the idle floor
	IdleAfter    time.Duration
	AdaptiveIdle bool // reduce the floor after a low-demand 30-second window
	RetryMin     time.Duration
	RetryMax     time.Duration
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
	batchFailed             bool
	renewed                 uint64
	demandStart             time.Time
	demandCount             int
	lowDemand               bool
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
	if opts.IdleSize < 0 || opts.IdleSize > opts.Size || opts.IdleAfter < 0 {
		return nil, fmt.Errorf("invalid idle pool limits")
	}
	if opts.IdleSize > 0 && opts.IdleAfter == 0 {
		opts.IdleAfter = 2 * time.Minute
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
	now := time.Now()
	p := &Pool{target: opts.Size, demandStart: now, lastDemand: now, lastShrink: now, opts: opts, factory: factory, logger: logger, ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1)}
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
		var retired *Entry
		var jobs []*Entry
		p.mu.Lock()
		now := time.Now()
		p.shrinkLocked(now)
		// Healthy slots refill independently; failures impose one shared cooldown.
		if !p.closed && p.ctx.Err() == nil && !now.Before(p.nextRetry) {
			for len(p.idle)+p.filling+len(jobs) < p.target {
				jobs = append(jobs, nil)
			}
			// At most one proactive replacement per batch. Keep the old entry until
			// success when spare capacity exists. At the hard cap retire at most one,
			// and never proactively remove the last ready connection.
			if len(jobs) == 0 && p.filling == 0 {
				if i := p.renewalIndexLocked(now); i >= 0 {
					e := p.idle[i]
					if len(p.idle) < p.opts.MaxSize {
						jobs = append(jobs, e)
					} else if len(p.idle) > 1 {
						p.idle = append(p.idle[:i], p.idle[i+1:]...)
						retired = e
						jobs = append(jobs, e)
					}
				}
			}
			if len(jobs) > 0 {
				p.batchFailed = false
			}
			p.filling += len(jobs)
			for range jobs {
				p.wg.Add(1)
			}
		}
		p.mu.Unlock()
		if retired != nil {
			closeUnused(retired.Conn)
		}
		// At the hard cap close the retired socket before opening its successor.
		for _, old := range jobs {
			go p.fill(old)
		}
		select {
		case <-p.ctx.Done():
			return
		case <-p.wake:
		case <-ticker.C:
		}
	}
}

// Failures share a cooldown window, so parallel failures cannot multiply
// backoff. A slow worker never prevents other vacant slots being replenished.
func (p *Pool) completeBatchLocked(err error) {
	if err == nil {
		if p.filling == 0 && !p.batchFailed {
			p.retry = 0
			p.nextRetry = time.Time{}
			p.unsupportedLogged = false
		}
		return
	}
	p.batchFailed = true
	if time.Now().Before(p.nextRetry) && !(errors.Is(err, ErrUnsupported) && p.retry < p.opts.RetryMax) {
		return
	}
	if errors.Is(err, ErrUnsupported) {
		p.retry = p.opts.RetryMax
	} else if p.retry == 0 {
		p.retry = p.opts.RetryMin
	} else if p.retry >= p.opts.RetryMax/2 {
		p.retry = p.opts.RetryMax
	} else {
		p.retry *= 2
	}
	if p.retry > p.opts.RetryMax {
		p.retry = p.opts.RetryMax
	}
	p.nextRetry = time.Now().Add(p.retry + time.Duration(rand.Float64()*float64(p.retry)/4))
}
func (p *Pool) fill(old *Entry) {
	defer p.wg.Done()
	ctx, cancel := context.WithTimeout(p.ctx, 35*time.Second)
	entry, err := p.factory(ctx)
	cancel()
	if err == nil {
		if entry == nil || entry.Conn == nil || entry.Reader == nil {
			err = fmt.Errorf("invalid prepared connection")
		} else {
			// Retire between 80% and 100% of the configured TTL, always before the
			// original upper bound. Start replacement another 20% TTL earlier.
			ttl := time.Duration(float64(p.opts.IdleTTL) * (0.8 + 0.2*rand.Float64()))
			entry.expires = time.Now().Add(ttl)
			entry.refreshAt = entry.expires.Add(-p.opts.IdleTTL / 5)
			err = entry.Conn.SetReadDeadline(entry.expires)
		}
	}
	p.mu.Lock()
	p.filling--
	if p.closed || p.ctx.Err() != nil {
		p.mu.Unlock()
		if entry != nil && entry.Conn != nil {
			closeUnused(entry.Conn)
		}
		return
	}
	p.completeBatchLocked(err)
	if err != nil {
		unsupported := errors.Is(err, ErrUnsupported) && !p.unsupportedLogged
		if unsupported {
			p.unsupportedLogged = true
		}
		p.mu.Unlock()
		if entry != nil && entry.Conn != nil {
			closeUnused(entry.Conn)
		}
		if p.logger != nil {
			p.logger.Debug("pool fill failed", "error", err)
			if unsupported {
				p.logger.Info("pool unsupported; retrying")
			}
		}
		p.signal()
		return
	}
	var retired *Entry
	if old != nil {
		for i, e := range p.idle {
			if e == old {
				p.idle = append(p.idle[:i], p.idle[i+1:]...)
				retired = old
				break
			}
		}
	}
	// Demand may have consumed the old entry, or the target may have shrunk.
	// Never close a handed-off connection or retain surplus replacements.
	keepIdleKeeper := old != nil && p.keeperNeedsRenewalLocked(time.Now())
	if len(p.idle) >= p.opts.MaxSize || (len(p.idle) >= p.target && !keepIdleKeeper) {
		p.mu.Unlock()
		closeUnused(entry.Conn)
		if retired != nil {
			closeUnused(retired.Conn)
		}
		p.signal()
		return
	}
	entry.done = make(chan struct{})
	p.idle = append(p.idle, entry)
	if old != nil {
		p.renewed++
	}
	p.wg.Add(1)
	go p.guard(entry)
	p.mu.Unlock()
	if p.logger != nil {
		if entry.QUICDuration > 0 {
			p.logger.Debug("pool prepared", "udp_tunnel_transport", "quic", "udp_quic_handshake_duration", entry.QUICDuration)
		} else {
			p.logger.Debug("pool prepared", "node_dns_duration", entry.DialTimings.NodeDNSDuration, "node_tcp_duration", entry.DialTimings.NodeTCPDuration, "tls_duration", entry.DialTimings.TLSDuration, "tls_resumed", entry.DialTimings.TLSResumed)
		}
	}
	if retired != nil {
		closeUnused(retired.Conn)
	}
	p.signal()
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
		closeUnused(entry.Conn)
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
		now := time.Now()
		p.updateDemandLocked(now)
		p.demandCount = min(3, p.demandCount+1)
		if p.demandCount > 2 {
			p.lowDemand = false
		}
		p.lastDemand = now
		if (p.opts.IdleSize > 0 || p.opts.AdaptiveIdle) && !p.lowDemand && p.target < p.opts.Size {
			// Demand restores the normal floor immediately without waiting for
			// shrink ticks; callers still never wait for background refill.
			p.target = p.opts.Size
		}
		// Grow only when demand exhausts ready capacity; never exceed MaxSize.
		if (!p.opts.AdaptiveIdle || !p.lowDemand) && len(p.idle) <= 1 && p.target < p.opts.MaxSize {
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
		// Entries are appended after successful preparation. Prefer the newest
		// ready channel; older ones remain guarded and expire/renew normally.
		last := len(p.idle) - 1
		entry := p.idle[last]
		p.idle[last] = nil
		p.idle = p.idle[:last]
		p.mu.Unlock()
		p.signal()
		if !time.Now().Before(entry.expires) {
			closeUnused(entry.Conn)
			continue
		}
		if err := entry.Conn.SetReadDeadline(time.Now()); err != nil {
			closeUnused(entry.Conn)
			continue
		}
		select {
		case <-entry.done:
		case <-ctx.Done():
			closeUnused(entry.Conn)
			return nil
		}
		var netErr net.Error
		if !errors.As(entry.guardErr, &netErr) || !netErr.Timeout() {
			closeUnused(entry.Conn)
			continue
		}
		if err := entry.Conn.SetReadDeadline(time.Time{}); err != nil {
			closeUnused(entry.Conn)
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
		closeUnused(entry.Conn)
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
	Renewed                    uint64
	Retry                      time.Duration
	Idle, Filling, Target, Max int
	HitRate                    float64
	LowDemand                  bool
}

func (p *Pool) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := Stats{LowDemand: p.lowDemand, Renewed: p.renewed, Retry: p.retry, Hits: p.hits, Misses: p.misses, Fallbacks: p.fallbacks, Idle: len(p.idle), Filling: p.filling, Target: p.target, Max: p.opts.MaxSize}
	if n := s.Hits + s.Misses; n > 0 {
		s.HitRate = 100 * float64(s.Hits) / float64(n)
	}
	return s
}
func (p *Pool) RecordFallback() { p.mu.Lock(); p.fallbacks++; p.mu.Unlock() }

// During idle shrink, one fresh keeper prevents a cluster of surplus expiries
// from exhausting ready capacity before a healthy renewal can finish. Renewal
// remains best effort when preparation exceeds the keeper's remaining lifetime.
func (p *Pool) keeperNeedsRenewalLocked(now time.Time) bool {
	for _, entry := range p.idle {
		if now.Before(entry.refreshAt) {
			return false
		}
	}
	return true
}

func (p *Pool) renewalIndexLocked(now time.Time) int {
	if len(p.idle) > p.target {
		if !p.keeperNeedsRenewalLocked(now) {
			return -1
		}
		oldest := 0
		for i, entry := range p.idle {
			if entry.expires.Before(p.idle[oldest].expires) {
				oldest = i
			}
		}
		return oldest
	}
	for i, entry := range p.idle {
		if !now.Before(entry.refreshAt) {
			return i
		}
	}
	return -1
}

func (p *Pool) shrinkLocked(now time.Time) {
	p.updateDemandLocked(now)
	floor := p.opts.Size
	if p.opts.AdaptiveIdle && p.lowDemand {
		floor = max(1, p.opts.IdleSize)
	} else if p.opts.IdleSize > 0 && now.Sub(p.lastDemand) >= p.opts.IdleAfter {
		floor = p.opts.IdleSize
	}
	quiet := now.Sub(p.lastDemand) >= 30*time.Second || (p.opts.AdaptiveIdle && p.lowDemand)
	if p.target > floor && quiet && now.Sub(p.lastShrink) >= 30*time.Second {
		p.target--
		p.lastShrink = now
	}
}

// A few periodic probes must not keep a full pool warm forever. The third
// request in a window immediately restores normal demand; only the floor and
// future renewal change, never ownership or expiry of handed-off connections.
func (p *Pool) updateDemandLocked(now time.Time) {
	if !p.opts.AdaptiveIdle {
		return
	}
	if now.Sub(p.demandStart) >= 30*time.Second {
		p.lowDemand = p.demandCount <= 2 || now.Sub(p.demandStart) >= time.Minute
		p.demandStart = now
		p.demandCount = 0
	}
}
