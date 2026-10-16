package datagram

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestResourcesLimitCacheEvictionAndOutstandingOwnership(t *testing.T) {
	r := NewResources(2, 8192)
	if !r.AcquireSocket() || !r.AcquireSocket() || r.AcquireSocket() {
		t.Fatal("socket cap")
	}
	r.ReleaseSocket()
	if !r.AcquireSocket() {
		t.Fatal("socket not released")
	}
	r.ReleaseSocket()
	r.ReleaseSocket()
	packets := make([]Packet, 4)
	for i := range packets {
		var err error
		packets[i], err = r.Borrow(1200)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.Borrow(1); !errors.Is(err, ErrResourceLimit) {
		t.Fatal("memory cap ignored")
	}
	packets[0].Release()
	if r.Stats().CachedBytes != 2048 {
		t.Fatal(r.Stats())
	}
	small, err := r.Borrow(1)
	if err != nil {
		t.Fatal("cached memory not evicted for another size", err)
	}
	if s := r.Stats(); s.BufferBytes > 8192 || s.CachedBytes != 0 || s.PeakBytes != 8192 {
		t.Fatal(s)
	}
	r.Close()
	for i := range packets {
		packets[i].Release()
	}
	small.Release()
	if s := r.Stats(); s.BufferBytes != 0 || s.Sockets != 0 || s.MemoryRejected != 1 || s.SocketRejected != 1 {
		t.Fatal(s)
	}
}

func TestResourcesConcurrentReuseAndNoWarmAllocation(t *testing.T) {
	r := NewResources(8, 65536)
	defer r.Close()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if p, err := r.Borrow(1200); err == nil {
					p.Data[0] = 1
					p.Release()
				}
			}
		}()
	}
	wg.Wait()
	if s := r.Stats(); s.BufferBytes != s.CachedBytes || s.PeakBytes > 65536 {
		t.Fatal(s)
	}
	if n := testing.AllocsPerRun(1000, func() {
		p, err := r.Borrow(1200)
		if err != nil {
			panic(err)
		}
		p.Release()
	}); n != 0 {
		t.Fatalf("warm pool allocations: %v", n)
	}
}

func TestManagedPacketQueueRejectionExpirationAndClose(t *testing.T) {
	r := NewResources(1, 8192)
	q := NewQueue(1, 2048, 10*time.Millisecond, nil, r)
	defer r.Close()
	first, _ := r.Borrow(100)
	if !q.Push(first) {
		t.Fatal("push")
	}
	second, _ := r.Borrow(100)
	if q.Push(second) {
		t.Fatal("full queue accepted")
	}
	second.Release()
	time.Sleep(20 * time.Millisecond)
	if !q.PushCopy([]byte("fresh")) {
		t.Fatal("expired owner not released")
	}
	p, ok := q.TryPop()
	if !ok || string(p.Data) != "fresh" {
		t.Fatal("bad payload")
	}
	if s := r.Stats(); s.BufferBytes-s.CachedBytes != 512 {
		t.Fatal("dequeued owner released too early", s)
	}
	p.Release()
	q.PushCopy([]byte("close"))
	q.Close()
	if s := r.Stats(); s.BufferBytes != s.CachedBytes {
		t.Fatal("queue retained managed owners", s)
	}
}
