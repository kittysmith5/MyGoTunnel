package datagram

import (
	"bytes"
	"testing"
	"time"
)

func requirePacket(t *testing.T, q interface{ TryPop() (Packet, bool) }) Packet {
	t.Helper()
	p, ok := q.TryPop()
	if !ok {
		t.Fatal("packet missing")
	}
	return p
}

func TestSmallSelectionExcludesRetainedDestinationAfterReap(t *testing.T) {
	r := NewResources(8, 1<<20)
	defer r.Close()
	q := NewKeyedQueue(2, 1<<20, time.Second, r)
	defer q.Close()
	if !q.PushKeyCopy([]byte("same"), bytes.Repeat([]byte{1}, 4000)) {
		t.Fatal("large packet rejected")
	}
	inFlight := requirePacket(t, q)
	defer inFlight.Release()
	oldFlow := inFlight.flow
	// Empty the original destination, then force metadata reclamation. A new
	// producer for the original key must remain excluded while this packet lives.
	for _, key := range []string{"first", "second"} {
		if !q.PushKeyCopy([]byte(key), []byte("other")) {
			t.Fatal("metadata churn rejected")
		}
		p := requirePacket(t, q)
		p.Release()
	}
	if q.flows["same"] != nil {
		t.Fatal("test did not reclaim old flow metadata")
	}
	key := []byte("same")
	if !q.PushKeyCopy(key, []byte("same-small")) || !q.PushKeyCopy([]byte("different"), []byte("other-small")) {
		t.Fatal("small packet rejected")
	}
	key[0] = 'x'
	if q.flows["same"] == oldFlow || len(q.flows) > q.limit {
		t.Fatal("new flow identity or metadata bound incorrect")
	}
	p, ok := q.TryPopSmallExcept(100, inFlight)
	if !ok || string(p.Data) != "other-small" {
		p.Release()
		t.Fatal("same destination overtook its retained packet")
	}
	p.Release()
	if p, ok := q.TryPopSmallExcept(100, inFlight); ok {
		p.Release()
		t.Fatal("retained destination was not excluded")
	}
	p = requirePacket(t, q)
	if string(p.Data) != "same-small" {
		t.Fatal("excluded packet was lost")
	}
	p.Release()
	inFlight.Release()
	q.Close()
	if s := r.Stats(); s.BufferBytes != s.CachedBytes {
		t.Fatal("retained flow leaked payload ownership", s)
	}
}

func TestSmallSelectionExcludesReplacedProducerAndKeepsAnonymousFlowsDistinct(t *testing.T) {
	for _, keyed := range []bool{false, true} {
		t.Run(map[bool]string{false: "anonymous", true: "same-key"}[keyed], func(t *testing.T) {
			r := NewResources(8, 1<<20)
			defer r.Close()
			q := NewFairQueue(4, 1<<20, time.Second, r)
			defer q.Close()
			old := q.NewFlow()
			if keyed {
				old = q.NewFlowKey("") // Empty is a valid owned key, distinct from anonymous.
			}
			if !old.PushCopy(make([]byte, 4000)) {
				t.Fatal("large packet rejected")
			}
			inFlight := requirePacket(t, q)
			defer inFlight.Release()
			old.Close()
			replacement := q.NewFlow()
			if keyed {
				replacement = q.NewFlowKey("")
			}
			if !replacement.PushCopy([]byte("replacement")) {
				t.Fatal("new producer rejected")
			}
			p, ok := q.TryPopSmallExcept(100, inFlight)
			if keyed && ok {
				p.Release()
				t.Fatal("same target's new producer overtook its old packet")
			}
			if !keyed {
				if !ok || string(p.Data) != "replacement" {
					t.Fatal("different anonymous producer was excluded")
				}
				p.Release()
			}
		})
	}
}

func TestSmallExclusionPreservesExpiryAndAdmissionFailure(t *testing.T) {
	r := NewResources(8, 262144)
	defer r.Close()
	q := NewKeyedQueue(2, 65000, time.Second, r)
	defer q.Close()
	if !q.PushKeyCopy([]byte("large"), make([]byte, 4000)) {
		t.Fatal("large packet rejected")
	}
	p := requirePacket(t, q)
	defer p.Release()
	if q.PushKeyCopy([]byte("oversize"), make([]byte, 65001)) || q.flows["oversize"] != nil {
		t.Fatal("failed admission retained a destination index")
	}
	if !q.PushKeyCopy([]byte("expiring"), []byte("old")) {
		t.Fatal("expiry packet rejected")
	}
	q.FairQueue.mu.Lock()
	f := q.flows["expiring"]
	q.nodes[f.head].packet.At = time.Now().Add(-2 * time.Second)
	q.FairQueue.mu.Unlock()
	if got, ok := q.TryPopSmallExcept(100, p); ok {
		got.Release()
		t.Fatal("expired packet was selected")
	}
	if q.Stats().ExpiredDrops != 1 || len(q.flows) > q.limit {
		t.Fatal("expiry accounting or metadata bound changed", q.Stats())
	}
	q.Close()
	if q.PushKeyCopy([]byte("closed"), []byte("rejected")) || q.flows["closed"] != nil {
		t.Fatal("closed queue retained a new destination")
	}
}

func TestKeyedQueueResourceFailureDoesNotPublishDestination(t *testing.T) {
	r := NewResources(8, 262144)
	defer r.Close()
	q := NewKeyedQueue(2, 65000, time.Second, r)
	defer q.Close()
	var held []Packet
	defer func() {
		for i := range held {
			held[i].Release()
		}
	}()
	for range 4 {
		p, err := r.Borrow(65536)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, p)
	}
	if q.PushKeyCopy([]byte("resource-rejected"), []byte("small")) || len(q.flows) != 0 {
		t.Fatal("resource-rejected flow was retained")
	}
	if q.Stats().ResourceDrops != 1 {
		t.Fatal("resource rejection was not counted", q.Stats())
	}
}
