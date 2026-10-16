// Package authlimit bounds repeated authentication failures by peer IP.
package authlimit

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var ErrLimited = errors.New("authentication rate limited")

type entry struct {
	start, blockedUntil, last time.Time
	failures                  int
}
type Limiter struct {
	mu                   sync.Mutex
	entries              map[string]entry
	window, block        time.Duration
	failures, maxEntries int
	nextSweep            time.Time
	limited              atomic.Uint64
	now                  func() time.Time
}

// New creates a bounded sliding-window failure limiter. The map is capped; when
// full it evicts expired entries then rejects unknown peers until capacity returns.
func New(maxEntries, failures int, window, block time.Duration) *Limiter {
	if maxEntries < 1 {
		maxEntries = 4096
	}
	if failures < 1 {
		failures = 5
	}
	if window <= 0 {
		window = time.Minute
	}
	if block <= 0 {
		block = time.Minute
	}
	return &Limiter{entries: make(map[string]entry), maxEntries: maxEntries, failures: failures, window: window, block: block, now: time.Now}
}
func PeerKey(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.String()
	}
	return host
}
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e, ok := l.entries[key]
	if !ok {
		if len(l.entries) >= l.maxEntries {
			if !now.Before(l.nextSweep) {
				l.evict(now)
				l.nextSweep = now.Add(l.window)
			}
			allowed := len(l.entries) < l.maxEntries
			if !allowed {
				l.limited.Add(1)
			}
			return allowed
		}
		return true
	}
	if now.Before(e.blockedUntil) {
		e.last = now
		l.entries[key] = e
		l.limited.Add(1)
		return false
	}
	if now.Sub(e.last) > l.window {
		delete(l.entries, key)
		return true
	}
	return true
}
func (l *Limiter) Failure(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e, ok := l.entries[key]
	if !ok {
		if len(l.entries) >= l.maxEntries {
			if !now.Before(l.nextSweep) {
				l.evict(now)
				l.nextSweep = now.Add(l.window)
			}
			if len(l.entries) >= l.maxEntries {
				return false
			}
		}
		e = entry{start: now}
	}
	if now.Sub(e.start) > l.window {
		e = entry{start: now}
	}
	e.failures++
	e.last = now
	if e.failures >= l.failures {
		e.blockedUntil = now.Add(l.block)
		e.failures = 0
		e.start = e.blockedUntil
	}
	l.entries[key] = e
	return true
}
func (l *Limiter) Limited() uint64    { return l.limited.Load() }
func (l *Limiter) Success(key string) { l.mu.Lock(); delete(l.entries, key); l.mu.Unlock() }
func (l *Limiter) evict(now time.Time) {
	for k, e := range l.entries {
		if !now.Before(e.blockedUntil) && now.Sub(e.last) > l.window {
			delete(l.entries, k)
		}
	}
}
