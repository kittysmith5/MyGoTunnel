package main

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	udpRetryInitial   = 100 * time.Millisecond
	udpRetryMaximum   = time.Second
	udpRetryRetention = time.Minute
)

type udpRetryEntry struct {
	until, last time.Time
	delay       time.Duration
	generation  uint64
}

// A session keeps at most one bounded record per target slot. Records contain
// owned header keys, never borrowed packet memory. Cancellation/resource limits
// do not enter the table, and successful responses remove failure history.
type udpRetryTable struct {
	mu       sync.Mutex
	entries  map[string]udpRetryEntry
	rejected atomic.Uint64
	next     atomic.Uint64
}

func newUDPRetryTable() *udpRetryTable {
	return &udpRetryTable{entries: make(map[string]udpRetryEntry)}
}
func (t *udpRetryTable) blocked(key string, now time.Time) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	entry, ok := t.entries[key]
	if ok && now.Sub(entry.last) >= udpRetryRetention {
		delete(t.entries, key)
		return false
	}
	blocked := ok && now.Before(entry.until)
	if blocked {
		t.rejected.Add(1)
	}
	return blocked
}
func (t *udpRetryTable) failure(key string, now time.Time) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failLocked(key, now, 0)
}
func (t *udpRetryTable) failureAttempt(target *udpTarget, now time.Time) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if target.retryContext != nil && target.retryContext.Err() != nil {
		return
	}
	t.failLocked(target.key, now, target.retryGeneration)
}
func (t *udpRetryTable) failLocked(key string, now time.Time, generation uint64) {
	entry, exists := t.entries[key]
	if exists && entry.generation > generation {
		return
	}
	delay := udpRetryInitial
	if exists && now.Sub(entry.last) < udpRetryRetention {
		delay = min(2*entry.delay, udpRetryMaximum)
	}
	if !exists && len(t.entries) >= udpTargetLimit {
		var oldestKey string
		var oldest time.Time
		for key, other := range t.entries {
			if oldest.IsZero() || other.last.Before(oldest) {
				oldest, oldestKey = other.last, key
			}
		}
		delete(t.entries, oldestKey)
	}
	t.entries[key] = udpRetryEntry{until: now.Add(delay), last: now, delay: delay, generation: generation}
}
func (t *udpRetryTable) success(key string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	delete(t.entries, key)
	t.mu.Unlock()
}
func (t *udpRetryTable) successAttempt(target *udpTarget) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if target.failureRecorded.Load() || (target.retryContext != nil && target.retryContext.Err() != nil) {
		return
	}
	if entry, ok := t.entries[target.key]; ok && entry.generation <= target.retryGeneration {
		delete(t.entries, target.key)
	}
}
func (t *udpRetryTable) expire(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for key, entry := range t.entries {
		if now.Sub(entry.last) >= udpRetryRetention {
			delete(t.entries, key)
		}
	}
}
func (t *udpRetryTable) count() int { t.mu.Lock(); defer t.mu.Unlock(); return len(t.entries) }
