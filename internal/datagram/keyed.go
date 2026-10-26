package datagram

import (
	"sync"
	"time"
)

// KeyedQueue provides a bounded producer-side destination index for FairQueue.
// Keys are copied only for newly admitted flows. Metadata is limited by packet
// capacity; empty entries are reclaimed under pressure, not scanned per packet.
type KeyedQueue struct {
	*FairQueue
	mu    sync.Mutex
	flows map[string]*FairFlow
	limit int
}

func NewKeyedQueue(packets, bytes int, age time.Duration, resources *Resources) *KeyedQueue {
	return &KeyedQueue{FairQueue: NewFairQueue(packets, bytes, age, resources), flows: make(map[string]*FairFlow), limit: packets}
}
func (q *KeyedQueue) reap() {
	q.FairQueue.mu.Lock()
	defer q.FairQueue.mu.Unlock()
	for key, f := range q.flows {
		if f.packets == 0 {
			delete(q.flows, key)
		}
	}
}
func (q *KeyedQueue) PushKeyCopy(key, data []byte) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if f := q.flows[string(key)]; f != nil {
		return f.PushCopy(data)
	}
	if len(q.flows) >= q.limit {
		q.reap()
	}
	f := q.NewFlow()
	if !f.PushCopy(data) {
		return false
	}
	// Admission may have emptied a victim; free its metadata before indexing.
	if len(q.flows) >= q.limit {
		q.reap()
	}
	q.flows[string(key)] = f
	return true
}
func (q *KeyedQueue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.FairQueue.Close()
	clear(q.flows)
}
