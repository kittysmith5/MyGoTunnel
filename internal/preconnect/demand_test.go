package preconnect

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestLowRateDemandShrinksAndBurstRestoresFloor(t *testing.T) {
	now := time.Now()
	p := &Pool{opts: Options{Size: 4, MaxSize: 16, AdaptiveIdle: true}, target: 4, demandStart: now, lastShrink: now, lastDemand: now, wake: make(chan struct{}, 1)}
	// One request every 20 seconds would continually reset the old idle timer.
	for i := 1; i <= 6; i++ {
		at := now.Add(time.Duration(i) * 20 * time.Second)
		p.updateDemandLocked(at)
		p.demandCount = min(3, p.demandCount+1)
		p.lastDemand = at
		p.shrinkLocked(at)
	}
	if p.target != 1 || !p.lowDemand {
		t.Fatal("periodic low-rate requests retained full pool", p.target, p.lowDemand)
	}
	// Three requests in one window restore normal warm capacity without waiting
	// for the next tick. Take remains nonblocking even when no entries are ready.
	p.demandStart = time.Now()
	p.demandCount = 0
	p.closed = false
	for range 3 {
		if e := p.Take(context.Background()); e != nil {
			t.Fatal("unexpected entry")
		}
	}
	if p.lowDemand || p.target < p.opts.Size {
		t.Fatal("burst did not restore floor", p.target)
	}
}
func TestDemandWindowRespectsExplicitFloorAndLegacy(t *testing.T) {
	now := time.Now()
	for _, adaptive := range []bool{false, true} {
		p := &Pool{opts: Options{Size: 4, MaxSize: 8, IdleSize: 2, AdaptiveIdle: adaptive, IdleAfter: time.Minute}, target: 4, demandStart: now, lastShrink: now, lastDemand: now}
		for i := 1; i <= 8; i++ {
			at := now.Add(time.Duration(i) * 20 * time.Second)
			p.updateDemandLocked(at)
			p.demandCount = min(3, p.demandCount+1)
			p.lastDemand = at
			p.shrinkLocked(at)
		}
		want := 4
		if adaptive {
			want = 2
		}
		if p.target != want {
			t.Fatalf("adaptive=%v target=%d want=%d", adaptive, p.target, want)
		}
	}
}

func TestAdaptiveIdleReducesRealRenewalWork(t *testing.T) {
	for _, size := range []int{2, 4} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			oldFactory, newFactory := &pipeFactory{}, &pipeFactory{}
			defer oldFactory.close()
			defer newFactory.close()
			old, e := New(Options{Size: size, MaxSize: size + 1, IdleTTL: 250 * time.Millisecond}, oldFactory.create, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer old.Close()
			updated, e := New(Options{Size: size, MaxSize: size + 1, IdleTTL: 250 * time.Millisecond, AdaptiveIdle: true}, newFactory.create, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer updated.Close()
			idle(t, old, size)
			idle(t, updated, size)
			// Advance only demand classification; live guard deadlines and actual
			// connection renewal continue to run normally at the accelerated test TTL.
			updated.mu.Lock()
			updated.demandStart = time.Now().Add(-time.Minute)
			for range size - 1 {
				updated.lastShrink = time.Now().Add(-time.Minute)
				updated.shrinkLocked(time.Now())
			}
			updated.mu.Unlock()
			updated.signal()
			idle(t, updated, 1)
			a, b := oldFactory.calls.Load(), newFactory.calls.Load()
			time.Sleep(900 * time.Millisecond)
			before, after := oldFactory.calls.Load()-a, newFactory.calls.Load()-b
			if before <= after || updated.Stats().Target != 1 {
				t.Fatal("idle renewal did not fall", before, after, updated.Stats())
			}
			t.Logf("idle size %d: actual factory calls in 900ms old=%d adaptive=%d", size, before, after)
		})
	}
}
