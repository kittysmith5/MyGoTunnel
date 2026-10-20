package datagram

import (
	"errors"
	"sync"
	"testing"
)

func TestResidentAdmissionPreservesTwoMaximumTransientBuffers(t *testing.T) {
	r := NewResources(8, 4*65536)
	defer r.Close()
	one, err := r.BorrowResident(65001)
	if err != nil {
		t.Fatal(err)
	}
	two, err := r.BorrowResident(65001)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.BorrowResident(65001); !errors.Is(err, ErrResourceLimit) {
		t.Fatal("third resident buffer consumed transient headroom", err)
	}
	incoming, err := r.Borrow(65000)
	if err != nil {
		t.Fatal("incoming frame lost reserved headroom", err)
	}
	response, err := r.Borrow(65000)
	if err != nil {
		t.Fatal("response copy lost reserved headroom", err)
	}
	if s := r.Stats(); s.BufferBytes != 4*65536 || s.ResidentBytes != 2*65536 || s.ResidentLimit != 2*65536 || s.TransientReserve != 2*65536 || s.ResidentRejected != 1 || s.MemoryRejected != 1 {
		t.Fatal(s)
	}
	one.Release()
	two.Release()
	incoming.Release()
	response.Release()
	if s := r.Stats(); s.ResidentBytes != 0 || s.BufferBytes != s.CachedBytes {
		t.Fatal("resident release or cache accounting", s)
	}
	r.Close()
	if s := r.Stats(); s.BufferBytes != 0 || s.CachedBytes != 0 || s.ResidentBytes != 0 {
		t.Fatal(s)
	}
}

func TestResidentAndTransientReuseOneCacheAndSurviveClose(t *testing.T) {
	r := NewResources(8, 3*65536)
	one, err := r.BorrowResident(65001)
	if err != nil {
		t.Fatal(err)
	}
	buffer := one.buffer
	one.Release()
	two, err := r.Borrow(65000)
	if err != nil || two.buffer != buffer {
		t.Fatal("resident cache was not reusable by frames", err)
	}
	if s := r.Stats(); s.ResidentBytes != 0 || s.CachedBytes != 0 {
		t.Fatal(s)
	}
	two.Release()
	three, err := r.BorrowResident(65001)
	if err != nil || three.buffer != buffer {
		t.Fatal("frame cache was not reusable by resident buffers", err)
	}
	r.Close()
	if s := r.Stats(); s.ResidentBytes != 65536 || s.BufferBytes != 65536 {
		t.Fatal("Close lost outstanding owner", s)
	}
	three.Release()
	if s := r.Stats(); s.ResidentBytes != 0 || s.BufferBytes != 0 {
		t.Fatal("release after Close leaked resident buffer", s)
	}
}

func TestConcurrentResidentAdmissionKeepsProcessHeadroom(t *testing.T) {
	r := NewResources(32, 4*65536)
	defer r.Close()
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for attempt := 0; attempt < 100; attempt++ {
				packet, err := r.BorrowResident(65001)
				if err != nil {
					continue
				}
				if s := r.Stats(); s.ResidentBytes > s.ResidentLimit || s.BufferBytes > s.MemoryLimit {
					t.Error("concurrent admission exceeded limits", s)
				}
				packet.Release()
			}
		}()
	}
	workers.Wait()
	if s := r.Stats(); s.ResidentBytes != 0 || s.BufferBytes != s.CachedBytes {
		t.Fatal(s)
	}
	if allocations := testing.AllocsPerRun(100, func() {
		packet, err := r.BorrowResident(65001)
		if err != nil {
			panic(err)
		}
		packet.Release()
	}); allocations != 0 {
		t.Fatalf("warm resident borrow allocated %.1f times", allocations)
	}
}
