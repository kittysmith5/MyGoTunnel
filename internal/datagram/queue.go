// Package datagram provides bounded, age-limited queues for tunneled UDP.
package datagram

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultMaxBytes = 1024 * 1024
	DefaultMaxAge   = 250 * time.Millisecond
)

// Packet retains its original queue time when forwarded to another queue.
// A successful Push transfers ownership of Data to the queue.
type Packet struct {
	Data   []byte
	At     time.Time
	buffer *buffer
}

// Release relinquishes this packet's ownership. Copies must not be released
// after ownership has been transferred to a queue or another consumer.
func (p *Packet) Release() {
	if p.buffer != nil {
		p.buffer.owner.release(p.buffer)
	}
	*p = Packet{}
}

func (p Packet) expired(now time.Time, maxAge time.Duration) bool {
	return !p.At.IsZero() && now.Sub(p.At) >= maxAge
}

// Budget bounds the combined payload bytes of several queues (e.g. targets in
// one association). Dequeued/in-flight packets are not included.
type Budget struct {
	limit int64
	used  atomic.Int64
}

func NewBudget(limit int) *Budget { return &Budget{limit: int64(limit)} }

// CanFit is an advisory snapshot. Admission still acquires the budget atomically.
// It lets the single target dispatcher reclaim expired queues only under pressure.
func (b *Budget) CanFit(n int) bool {
	return n >= 0 && (b == nil || int64(n) <= b.limit-b.used.Load())
}

func (b *Budget) acquire(n int) bool {
	if b == nil {
		return true
	}
	for {
		old := b.used.Load()
		if old+int64(n) > b.limit {
			return false
		}
		if b.used.CompareAndSwap(old, old+int64(n)) {
			return true
		}
	}
}

func (b *Budget) release(n int) {
	if b != nil {
		b.used.Add(-int64(n))
	}
}

type Stats struct {
	Packets, Bytes, PeakBytes, Flows, PeakFlows          int
	FullDrops, ExpiredDrops, ResourceDrops, EvictedDrops uint64
}

// Queue supports concurrent producers and one consumer. Payload ownership is
// transferred on admission and relinquished on dequeue or Close.
type Queue struct {
	mu        sync.Mutex
	ring      []Packet
	head      int
	size      int
	bytes     int
	max       int
	age       time.Duration
	budget    *Budget
	resources *Resources
	ready     chan struct{}
	stats     Stats
	closed    bool
}

func NewQueue(packets, bytes int, age time.Duration, budget *Budget, resources ...*Resources) *Queue {
	if packets <= 0 || bytes <= 0 || age <= 0 {
		panic("invalid datagram queue capacity")
	}
	q := &Queue{ring: make([]Packet, packets), max: bytes, age: age, budget: budget, ready: make(chan struct{}, 1)}
	if len(resources) > 0 {
		q.resources = resources[0]
	}
	return q
}

func (q *Queue) Ready() <-chan struct{} { return q.ready }

func (q *Queue) Resources() *Resources {
	if q.resources != nil {
		return q.resources
	}
	return DefaultResources
}

func (q *Queue) notify() {
	select {
	case q.ready <- struct{}{}:
	default:
	}
}

// PushCopy does not allocate or copy the payload if admission fails. It is safe
// to reuse data as soon as this method returns.
func (q *Queue) PushCopy(data []byte) bool {
	return q.push(Packet{Data: data}, true)
}

func (q *Queue) Push(p Packet) bool { return q.push(p, false) }

func (q *Queue) push(p Packet, copyData bool) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := time.Now()
	if q.closed {
		return false
	}
	q.expire(now)
	if p.At.IsZero() {
		p.At = now
	} else if p.expired(now, q.age) {
		q.stats.ExpiredDrops++
		return false
	}
	n := len(p.Data)
	if q.size == len(q.ring) || n > q.max-q.bytes || !q.budget.acquire(n) {
		q.stats.FullDrops++
		return false
	}
	if copyData {
		if q.resources != nil {
			owned, err := q.resources.Borrow(n)
			if err != nil {
				q.budget.release(n)
				q.stats.ResourceDrops++
				return false
			}
			copy(owned.Data, p.Data)
			owned.At = p.At
			p = owned
		} else {
			p.Data = append([]byte(nil), p.Data...)
		}
	}
	q.ring[(q.head+q.size)%len(q.ring)] = p
	q.size++
	q.bytes += n
	q.stats.PeakBytes = max(q.stats.PeakBytes, q.bytes)
	q.notify()
	return true
}

func (q *Queue) remove() Packet {
	p := q.ring[q.head]
	q.ring[q.head] = Packet{}
	q.head = (q.head + 1) % len(q.ring)
	q.size--
	q.bytes -= len(p.Data)
	q.budget.release(len(p.Data))
	return p
}

func (q *Queue) expire(now time.Time) {
	for q.size > 0 && q.ring[q.head].expired(now, q.age) {
		p := q.remove()
		p.Release()
		q.stats.ExpiredDrops++
	}
}

// Expire releases packets whose queue lifetime has ended and returns the next
// queued expiry, or zero when empty. A shared-budget owner can reclaim a blocked
// consumer's stale packets without waking or canceling its network operation.
func (q *Queue) Expire(now time.Time) time.Time {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.expire(now)
	if q.size == 0 {
		return time.Time{}
	}
	return q.ring[q.head].At.Add(q.age)
}

func (q *Queue) TryPop() (Packet, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.expire(time.Now())
	if q.size == 0 {
		return Packet{}, false
	}
	p := q.remove()
	if q.size > 0 {
		q.notify()
	}
	return p, true
}

func (q *Queue) Pop(ctx context.Context) (Packet, bool) {
	for ctx.Err() == nil {
		if p, ok := q.TryPop(); ok {
			return p, true
		}
		q.mu.Lock()
		closed := q.closed
		q.mu.Unlock()
		if closed {
			return Packet{}, false
		}
		select {
		case <-q.ready:
		case <-ctx.Done():
			return Packet{}, false
		}
	}
	return Packet{}, false
}

// Close rejects future producers and releases all queued bytes.
func (q *Queue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.expire(time.Now())
	q.closed = true
	for q.size > 0 {
		p := q.remove()
		p.Release()
	}
	q.notify() // wake an idle Pop so it can observe closed
}

func (q *Queue) Stats() Stats {
	q.mu.Lock()
	defer q.mu.Unlock()
	s := q.stats
	s.Packets, s.Bytes = q.size, q.bytes
	return s
}
