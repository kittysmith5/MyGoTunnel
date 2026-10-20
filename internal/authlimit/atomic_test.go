package authlimit

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestAuthenticateSerializesConcurrentFailureThreshold(t *testing.T) {
	const attempts, threshold = 64, 5
	limiter := New(8, threshold, time.Minute, time.Minute)
	start := make(chan struct{})
	results := make(chan error, attempts)
	var workers sync.WaitGroup
	for i := 0; i < attempts; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); <-start; results <- limiter.Authenticate("peer", false) }()
	}
	close(start)
	workers.Wait()
	close(results)
	rejected, limited := 0, 0
	for err := range results {
		switch {
		case errors.Is(err, ErrRejected):
			rejected++
		case errors.Is(err, ErrLimited):
			limited++
		default:
			t.Fatalf("unexpected authentication result %v", err)
		}
	}
	if rejected != threshold || limited != attempts-threshold || limiter.Limited() != uint64(limited) {
		t.Fatalf("rejected=%d limited=%d counter=%d", rejected, limited, limiter.Limited())
	}
	if err := limiter.Authenticate("peer", true); !errors.Is(err, ErrLimited) {
		t.Fatalf("correct credentials cleared active block: %v", err)
	}
}

func TestAuthenticateCapacityRecoveryAndSuccessfulReset(t *testing.T) {
	limiter := New(1, 2, time.Minute, time.Minute)
	now := time.Now()
	limiter.now = func() time.Time { return now }
	if err := limiter.Authenticate("known", false); !errors.Is(err, ErrRejected) {
		t.Fatal(err)
	}
	// Even correct credentials for an unknown peer must respect a full table.
	if err := limiter.Authenticate("unknown", true); !errors.Is(err, ErrLimited) {
		t.Fatal(err)
	}
	if err := limiter.Authenticate("known", true); err != nil {
		t.Fatal(err)
	}
	if len(limiter.entries) != 0 {
		t.Fatal("successful comparison did not clear failures")
	}
	if err := limiter.Authenticate("other", false); !errors.Is(err, ErrRejected) {
		t.Fatal(err)
	}
	if err := limiter.Authenticate("other", false); !errors.Is(err, ErrRejected) {
		t.Fatal(err)
	}
	if err := limiter.Authenticate("other", true); !errors.Is(err, ErrLimited) {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if err := limiter.Authenticate("other", true); err != nil {
		t.Fatalf("expired block did not recover: %v", err)
	}
}

func TestAuthenticateConcurrentPeersCannotOverfillState(t *testing.T) {
	limiter := New(1, 2, time.Minute, time.Minute)
	results := make(chan error, 2)
	start := make(chan struct{})
	for _, peer := range []string{"one", "two"} {
		go func(key string) { <-start; results <- limiter.Authenticate(key, false) }(peer)
	}
	close(start)
	one, two := <-results, <-results
	if !(errors.Is(one, ErrRejected) && errors.Is(two, ErrLimited) || errors.Is(two, ErrRejected) && errors.Is(one, ErrLimited)) {
		t.Fatalf("expected one recorded failure and one capacity rejection: %v, %v", one, two)
	}
	if len(limiter.entries) != 1 {
		t.Fatalf("entries=%d", len(limiter.entries))
	}
}
