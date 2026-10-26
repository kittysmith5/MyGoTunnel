package datagram

import (
	"bytes"
	"testing"
	"time"
)

func TestKeyedQueueProtectsNewDestinationAndBoundsMetadata(t *testing.T) {
	r := NewResources(8, 1<<20)
	defer r.Close()
	q := NewKeyedQueue(8, 65000, time.Second, r)
	defer q.Close()
	large := bytes.Repeat([]byte{1}, 1200)
	for i := 0; i < 8; i++ {
		if !q.PushKeyCopy([]byte("bulk"), large) {
			t.Fatal("single flow lost capacity")
		}
	}
	if !q.PushKeyCopy([]byte("dns"), []byte("query")) {
		t.Fatal("bulk excluded new flow")
	}
	found := false
	for i := 0; i < 2; i++ {
		p, ok := q.TryPop()
		if !ok {
			t.Fatal("missing packet")
		}
		if string(p.Data) == "query" {
			found = true
		}
		p.Release()
	}
	if !found || q.Stats().EvictedDrops != 1 {
		t.Fatal("interactive flow not scheduled", q.Stats())
	}
	for i := 0; i < 1000; i++ {
		key := []byte{byte(i >> 8), byte(i)}
		q.PushKeyCopy(key, []byte{1})
		p, ok := q.TryPop()
		if ok {
			p.Release()
		}
		if len(q.flows) > 8 {
			t.Fatal("unbounded flow metadata")
		}
	}
	q.Close()
	if r.Stats().BufferBytes != r.Stats().CachedBytes {
		t.Fatal("owned packet leaked")
	}
}
func TestKeyedQueueOwnsKeyAndExpires(t *testing.T) {
	r := NewResources(2, 262144)
	defer r.Close()
	q := NewKeyedQueue(2, 65000, time.Millisecond, r)
	defer q.Close()
	key := []byte("one")
	if !q.PushKeyCopy(key, []byte{1}) {
		t.Fatal("admission failed")
	}
	key[0] = 'x'
	if q.flows["one"] == nil {
		t.Fatal("borrowed key escaped")
	}
	q.Expire(time.Now().Add(time.Second))
	if p, ok := q.TryPop(); ok {
		p.Release()
		t.Fatal("expired packet retained")
	}
	if q.Stats().ExpiredDrops != 1 {
		t.Fatal(q.Stats())
	}
}

func TestSmallSelectionPreservesDestinationOrder(t *testing.T) {
	r := NewResources(2, 262144)
	defer r.Close()
	q := NewKeyedQueue(4, 65000, time.Second, r)
	defer q.Close()
	q.PushKeyCopy([]byte("one"), make([]byte, 4000))
	q.PushKeyCopy([]byte("one"), []byte("same-flow-small"))
	q.PushKeyCopy([]byte("two"), []byte("other"))
	p, ok := q.TryPopSmall(100)
	if !ok || string(p.Data) != "other" {
		t.Fatal("wrong destination overtook its head")
	}
	p.Release()
	if p, ok = q.TryPopSmall(100); ok {
		p.Release()
		t.Fatal("reordered a destination")
	}
}
