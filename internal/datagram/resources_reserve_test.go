package datagram

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestSocketReserveAdmissionIsAtomicUnderConcurrentFills(t *testing.T) {
	r := NewResources(32, 1<<20)
	defer r.Close()
	var tried, workers sync.WaitGroup
	var acquired atomic.Int64
	start, release := make(chan struct{}), make(chan struct{})
	for range 96 {
		tried.Add(1)
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			ok := r.AcquireSocketWithReserve(1)
			if ok {
				acquired.Add(1)
			}
			tried.Done()
			<-release
			if ok {
				r.ReleaseSocket()
			}
		}()
	}
	close(start)
	tried.Wait()
	defer func() { close(release); workers.Wait() }()
	if acquired.Load() != 31 || r.Stats().Sockets != 31 {
		t.Fatal("concurrent preparation consumed reserved slot", acquired.Load(), r.Stats())
	}
	if !r.AcquireSocket() {
		t.Fatal("foreground could not acquire its reserved slot")
	}
	if r.AcquireSocket() {
		t.Fatal("foreground bypassed the total socket cap")
	}
	r.ReleaseSocket()
}

func TestSocketReserveRejectsInvalidOrUnavailableHeadroom(t *testing.T) {
	for _, reserve := range []int{-1, 2, 3, int(^uint(0) >> 1)} {
		r := NewResources(2, 1<<20)
		if r.AcquireSocketWithReserve(reserve) || r.Stats().Sockets != 0 {
			t.Fatal("invalid headroom acquired a socket", reserve, r.Stats())
		}
		r.Close()
	}
	r := NewResources(2, 1<<20)
	if !r.AcquireSocketWithReserve(1) || r.AcquireSocketWithReserve(1) || !r.AcquireSocket() {
		t.Fatal("low budget did not preserve exactly one foreground slot", r.Stats())
	}
	r.ReleaseSocket()
	r.ReleaseSocket()
	r.Close()
	if r.AcquireSocketWithReserve(0) {
		t.Fatal("closed resources admitted a socket")
	}
}
