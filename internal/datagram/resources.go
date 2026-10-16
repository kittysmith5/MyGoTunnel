package datagram

import (
	"errors"
	"sync"
)

const (
	DefaultMaxSockets  = 1024
	DefaultMemoryLimit = 64 << 20
	cachePerClass      = 16
)

var ErrResourceLimit = errors.New("UDP process resource limit")

// DefaultResources is shared by standalone handlers. Production run functions
// create one configured instance and share it across every association.
var DefaultResources = NewResources(DefaultMaxSockets, DefaultMemoryLimit)

var bufferSizes = [...]int{512, 2048, 8192, 32768, 65536}

type buffer struct {
	data  []byte
	owner *Resources
	class int
}

// Resources bounds UDP socket reservations and managed buffer capacities,
// including idle cached buffers. It is not an RSS or total Go heap limit.
type Resources struct {
	mu                                                  sync.Mutex
	maxSockets, limit                                   int
	sockets, bytes, cached, peak                        int
	free                                                [len(bufferSizes)][]*buffer
	closed                                              bool
	socketRejected, memoryRejected                      uint64
	sessions, sessionErrors, writeErrors, writeTimeouts uint64
	ends                                                TerminationStats
}

type TerminationStats struct{ EOF, Timeout, Reset, Truncated, Canceled, Closed, Other uint64 }

type ResourceStats struct {
	Sockets, MaxSockets, BufferBytes, CachedBytes, PeakBytes, MemoryLimit int
	SocketRejected, MemoryRejected                                        uint64
	Sessions, SessionErrors, WriteErrors, WriteTimeouts                   uint64
	Terminations                                                          TerminationStats
}

func NewResources(sockets, bytes int) *Resources {
	if sockets <= 0 || bytes <= 0 {
		panic("invalid UDP process limits")
	}
	r := &Resources{maxSockets: sockets, limit: bytes}
	for i := range r.free {
		r.free[i] = make([]*buffer, 0, cachePerClass)
	}
	return r
}

func SelectResources(resources []*Resources) *Resources {
	if len(resources) > 0 && resources[0] != nil {
		return resources[0]
	}
	return DefaultResources
}

func (r *Resources) AcquireSocket() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.sockets >= r.maxSockets {
		r.socketRejected++
		return false
	}
	r.sockets++
	return true
}

func (r *Resources) ReleaseSocket() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sockets--
}

// Borrow returns a single-owner packet. Release it on rejection, expiration,
// consumption or shutdown; a successful queue Push transfers that obligation.
func (r *Resources) Borrow(n int) (Packet, error) {
	class := 0
	for class < len(bufferSizes) && n > bufferSizes[class] {
		class++
	}
	if n < 0 || class == len(bufferSizes) {
		return Packet{}, ErrResourceLimit
	}
	r.mu.Lock()
	if r.closed {
		r.memoryRejected++
		r.mu.Unlock()
		return Packet{}, ErrResourceLimit
	}
	free := r.free[class]
	if len(free) > 0 {
		b := free[len(free)-1]
		free[len(free)-1] = nil
		r.free[class] = free[:len(free)-1]
		r.cached -= len(b.data)
		r.mu.Unlock()
		return Packet{Data: b.data[:n], buffer: b}, nil
	}
	size := bufferSizes[class]
	if size > r.limit-r.bytes {
		r.evictLocked()
	}
	if size > r.limit-r.bytes {
		r.memoryRejected++
		r.mu.Unlock()
		return Packet{}, ErrResourceLimit
	}
	r.bytes += size
	r.peak = max(r.peak, r.bytes)
	r.mu.Unlock()
	b := &buffer{data: make([]byte, size), owner: r, class: class}
	return Packet{Data: b.data[:n], buffer: b}, nil
}

func (r *Resources) release(b *buffer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed && len(r.free[b.class]) < cachePerClass {
		r.free[b.class] = append(r.free[b.class], b)
		r.cached += len(b.data)
	} else {
		r.bytes -= len(b.data)
	}
}

func (r *Resources) evictLocked() {
	for i, free := range r.free {
		for j, b := range free {
			r.bytes -= len(b.data)
			r.cached -= len(b.data)
			free[j] = nil
		}
		r.free[i] = free[:0]
	}
}

// Close releases cached buffers; outstanding owners can still Release safely.
func (r *Resources) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.evictLocked()
}

func (r *Resources) RecordSession(reason string, writeFailed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions++
	if reason != "eof" {
		r.sessionErrors++
	}
	if writeFailed {
		r.writeErrors++
	}
	if writeFailed && reason == "timeout" {
		r.writeTimeouts++
	}
	switch reason {
	case "eof":
		r.ends.EOF++
	case "timeout":
		r.ends.Timeout++
	case "reset":
		r.ends.Reset++
	case "truncated":
		r.ends.Truncated++
	case "canceled":
		r.ends.Canceled++
	case "closed":
		r.ends.Closed++
	default:
		r.ends.Other++
	}
}

func (r *Resources) Stats() ResourceStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return ResourceStats{Sockets: r.sockets, MaxSockets: r.maxSockets, BufferBytes: r.bytes, CachedBytes: r.cached, PeakBytes: r.peak, MemoryLimit: r.limit,
		SocketRejected: r.socketRejected, MemoryRejected: r.memoryRejected, Sessions: r.sessions, SessionErrors: r.sessionErrors, WriteErrors: r.writeErrors, WriteTimeouts: r.writeTimeouts, Terminations: r.ends}
}
