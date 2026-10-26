package datagram

import (
	"container/heap"
	"sync"
	"time"
)

// FairQueue shares a fixed packet/byte budget across response flows. Flows take
// turns on dequeue. Under pressure a less backlogged flow may evict a packet
// from the largest backlog, so a burst cannot exclude a new interactive flow.
// Packet storage and heap entries are bounded by the total packet capacity.
// Empty flows are retained only by their producer, never by the queue.
type FairQueue struct {
	mu                     sync.Mutex
	nodes                  []fairNode
	free, size, bytes, max int
	age                    time.Duration
	resources              *Resources
	ready, expiryChanged   chan struct{}
	first                  *FairFlow
	largest                flowHeap
	nextExpiry             time.Time
	stats                  Stats
	closed                 bool
}
type fairNode struct {
	packet Packet
	next   int
}
type FairFlow struct {
	parent                                *FairQueue
	head, tail, packets, bytes, heapIndex int
	next, prev                            *FairFlow
	closed                                bool
}
type flowHeap []*FairFlow

func (h flowHeap) Len() int { return len(h) }
func (h flowHeap) Less(i, j int) bool {
	if h[i].bytes != h[j].bytes {
		return h[i].bytes > h[j].bytes
	}
	return h[i].packets > h[j].packets
}
func (h flowHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i]; h[i].heapIndex = i; h[j].heapIndex = j }
func (h *flowHeap) Push(x any)   { f := x.(*FairFlow); f.heapIndex = len(*h); *h = append(*h, f) }
func (h *flowHeap) Pop() any {
	a := *h
	f := a[len(a)-1]
	a[len(a)-1] = nil
	*h = a[:len(a)-1]
	f.heapIndex = -1
	return f
}

func NewFairQueue(packets, bytes int, age time.Duration, resources *Resources) *FairQueue {
	if packets <= 0 || bytes <= 0 || age <= 0 {
		panic("invalid fair datagram queue capacity")
	}
	if resources == nil {
		resources = DefaultResources
	}
	q := &FairQueue{nodes: make([]fairNode, packets), max: bytes, age: age, resources: resources, ready: make(chan struct{}, 1), expiryChanged: make(chan struct{}, 1), largest: make(flowHeap, 0, packets)}
	for i := range q.nodes {
		q.nodes[i].next = i + 1
	}
	q.nodes[packets-1].next = -1
	return q
}
func (q *FairQueue) NewFlow() *FairFlow {
	return &FairFlow{parent: q, head: -1, tail: -1, heapIndex: -1}
}
func (q *FairQueue) Ready() <-chan struct{}         { return q.ready }
func (q *FairQueue) ExpiryChanged() <-chan struct{} { return q.expiryChanged }
func (q *FairQueue) Resources() *Resources          { return q.resources }
func (f *FairFlow) Resources() *Resources           { return f.parent.resources }
func (f *FairFlow) Close()                          { q := f.parent; q.mu.Lock(); f.closed = true; q.mu.Unlock() }
func (q *FairQueue) notify() {
	select {
	case q.ready <- struct{}{}:
	default:
	}
}
func (q *FairQueue) activate(f *FairFlow) {
	if q.first == nil {
		q.first = f
		f.next = f
		f.prev = f
	} else {
		last := q.first.prev
		f.prev = last
		f.next = q.first
		last.next = f
		q.first.prev = f
	}
	heap.Push(&q.largest, f)
	q.stats.PeakFlows = max(q.stats.PeakFlows, len(q.largest))
}
func (q *FairQueue) removeHead(f *FairFlow) Packet {
	i := f.head
	n := &q.nodes[i]
	p := n.packet
	f.head = n.next
	n.packet = Packet{}
	n.next = q.free
	q.free = i
	f.packets--
	f.bytes -= len(p.Data)
	q.size--
	q.bytes -= len(p.Data)
	if f.packets == 0 {
		f.tail = -1
		heap.Remove(&q.largest, f.heapIndex)
		if f.next == f {
			q.first = nil
		} else {
			f.prev.next = f.next
			f.next.prev = f.prev
			if q.first == f {
				q.first = f.next
			}
		}
		f.next = nil
		f.prev = nil
	} else {
		heap.Fix(&q.largest, f.heapIndex)
	}
	return p
}
func (q *FairQueue) expireFlow(f *FairFlow, now time.Time) {
	for f.packets > 0 && q.nodes[f.head].packet.expired(now, q.age) {
		p := q.removeHead(f)
		p.Release()
		q.stats.ExpiredDrops++
	}
}
func (q *FairQueue) expireAll(now time.Time) time.Time {
	q.nextExpiry = time.Time{}
	// The heap order changes on removal. Walking the RR ring with a captured
	// successor keeps every original flow visited exactly once.
	remaining := len(q.largest)
	f := q.first
	for i := 0; i < remaining; i++ {
		next := f.next
		q.expireFlow(f, now)
		if f.packets > 0 {
			expiry := q.nodes[f.head].packet.At.Add(q.age)
			if q.nextExpiry.IsZero() || expiry.Before(q.nextExpiry) {
				q.nextExpiry = expiry
			}
		}
		f = next
	}
	return q.nextExpiry
}
func (q *FairQueue) Expire(now time.Time) time.Time {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.expireAll(now)
}
func (f *FairFlow) PushCopy(data []byte) bool {
	q := f.parent
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || f.closed {
		return false
	}
	now := time.Now()
	q.expireFlow(f, now)
	if len(data) > q.max {
		q.stats.FullDrops++
		return false
	}
	if (q.free < 0 || len(data) > q.max-q.bytes) && !q.nextExpiry.IsZero() && !now.Before(q.nextExpiry) {
		q.expireAll(now)
	}
	for q.free < 0 || len(data) > q.max-q.bytes {
		if !q.evictFor(f, len(data)) {
			q.stats.FullDrops++
			return false
		}
	}
	p, err := q.resources.Borrow(len(data))
	if err != nil && !q.nextExpiry.IsZero() && !now.Before(q.nextExpiry) {
		q.expireAll(now)
		p, err = q.resources.Borrow(len(data))
	}
	// Managed memory can fill before logical byte/packet capacity because pool
	// classes and other associations also consume it. Reclaim this queue's larger
	// backlogs when possible, without reaching into another association's owners.
	for err != nil && q.evictFor(f, len(data)) {
		p, err = q.resources.Borrow(len(data))
	}
	if err != nil {
		q.stats.ResourceDrops++
		return false
	}
	copy(p.Data, data)
	p.At = now
	i := q.free
	q.free = q.nodes[i].next
	q.nodes[i] = fairNode{packet: p, next: -1}
	empty := f.packets == 0
	if empty {
		f.head = i
	} else {
		q.nodes[f.tail].next = i
	}
	f.tail = i
	f.packets++
	f.bytes += len(data)
	q.size++
	q.bytes += len(data)
	if empty {
		q.activate(f)
	} else {
		heap.Fix(&q.largest, f.heapIndex)
	}
	q.stats.PeakBytes = max(q.stats.PeakBytes, q.bytes)
	expiry := now.Add(q.age)
	if q.nextExpiry.IsZero() || expiry.Before(q.nextExpiry) {
		q.nextExpiry = expiry
		select {
		case q.expiryChanged <- struct{}{}:
		default:
		}
	}
	q.notify()
	return true
}
func (q *FairQueue) evictFor(incoming *FairFlow, n int) bool {
	if len(q.largest) == 0 {
		return false
	}
	victim := q.largest[0]
	if victim == incoming || (victim.bytes <= incoming.bytes+n && victim.packets <= incoming.packets+1) {
		return false
	}
	p := q.removeHead(victim)
	p.Release()
	q.stats.FullDrops++
	q.stats.EvictedDrops++
	return true
}

func (q *FairQueue) TryPop() (Packet, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := time.Now()
	for q.first != nil {
		f := q.first
		q.expireFlow(f, now)
		if f.packets == 0 {
			continue
		}
		p := q.removeHead(f)
		if f.packets > 0 {
			q.first = f.next
		}
		if q.size > 0 {
			q.notify()
		}
		return p, true
	}
	return Packet{}, false
}
func (q *FairQueue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	q.expireAll(time.Now())
	for q.first != nil {
		p := q.removeHead(q.first)
		p.Release()
	}
	q.nextExpiry = time.Time{}
	q.notify()
}
func (q *FairQueue) Stats() Stats {
	q.mu.Lock()
	defer q.mu.Unlock()
	s := q.stats
	s.Packets = q.size
	s.Bytes = q.bytes
	s.Flows = len(q.largest)
	return s
}

// TryPopSmall selects only a flow's head, never reordering one destination.
// A QUIC fragment sender uses it between bounded quanta while retaining one
// large packet. The scan is bounded by packet capacity and adds no metadata.
func (q *FairQueue) TryPopSmall(maxSize int) (Packet, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := time.Now()
	f := q.first
	remaining := len(q.largest)
	for i := 0; i < remaining && f != nil; i++ {
		next := f.next
		q.expireFlow(f, now)
		if f.packets > 0 && len(q.nodes[f.head].packet.Data) <= maxSize {
			p := q.removeHead(f)
			if f.packets > 0 {
				q.first = f.next
			}
			if q.size > 0 {
				q.notify()
			}
			return p, true
		}
		f = next
	}
	return Packet{}, false
}
