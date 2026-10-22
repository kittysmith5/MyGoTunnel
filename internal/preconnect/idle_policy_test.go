package preconnect

import (
	"context"
	"testing"
	"time"
)

func TestIdlePolicyValidationAndDefaultFloor(t *testing.T) {
	f := &pipeFactory{}
	defer f.close()
	for _, opts := range []Options{{Size: 4, IdleSize: -1}, {Size: 4, IdleSize: 5}, {Size: 4, IdleSize: 1, IdleAfter: -time.Second}} {
		p, err := New(opts, f.create, nil)
		if err == nil {
			p.Close()
			t.Fatalf("accepted invalid options: %+v", opts)
		}
	}
	now := time.Now()
	p := &Pool{opts: Options{Size: 4}, target: 4, lastDemand: now.Add(-time.Hour), lastShrink: now.Add(-time.Hour)}
	p.shrinkLocked(now)
	if p.target != 4 {
		t.Fatal("default idle floor changed", p.target)
	}
	p.opts.IdleSize, p.opts.IdleAfter = 1, 2*time.Minute
	p.lastDemand = now.Add(-time.Minute)
	p.shrinkLocked(now)
	if p.target != 4 {
		t.Fatal("shrunk before idle interval")
	}
	p.lastDemand = now.Add(-3 * time.Minute)
	p.shrinkLocked(now)
	if p.target != 3 {
		t.Fatal("did not shrink one slot", p.target)
	}
	p.shrinkLocked(now.Add(time.Second))
	if p.target != 3 {
		t.Fatal("ignored shrink cadence")
	}
	p.shrinkLocked(now.Add(30 * time.Second))
	p.shrinkLocked(now.Add(60 * time.Second))
	p.shrinkLocked(now.Add(90 * time.Second))
	if p.target != 1 {
		t.Fatal("idle floor violated", p.target)
	}
}

func forceIdleFloor(p *Pool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	p.lastDemand = now.Add(-time.Hour)
	for p.target > p.opts.IdleSize {
		p.lastShrink = now.Add(-time.Hour)
		p.shrinkLocked(now)
	}
}

func TestIdlePolicySkipsSurplusRenewalAndRestoresOnDemand(t *testing.T) {
	f := &pipeFactory{}
	defer f.close()
	p, err := New(Options{Size: 4, MaxSize: 4, IdleTTL: time.Hour, IdleSize: 1}, f.create, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	idle(t, p, 4)
	forceIdleFloor(p)
	p.mu.Lock()
	for _, entry := range p.idle {
		entry.refreshAt = time.Now().Add(-time.Second)
	}
	p.mu.Unlock()
	p.signal()
	// A manager tick must not create useless replacements for excess entries.
	time.Sleep(150 * time.Millisecond)
	if f.calls.Load() != 4 {
		t.Fatal("renewed surplus connections while shrinking", f.calls.Load())
	}
	entry := p.Take(context.Background())
	if entry == nil || p.Stats().Target != 4 {
		t.Fatal("demand did not restore normal floor", p.Stats())
	}
	defer entry.Conn.Close()
	// The handed-off stream remains usable after pool shutdown.
	p.Close()
	if err := entry.Conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal("idle shrink closed a handed-off connection", err)
	}
}

// Compare renewal work with the same factory/TTL, advancing only idle age and
// refresh points. This measures work reduction, not network latency or P95.
func TestIdlePolicyControlledRenewalWork(t *testing.T) {
	for _, idleSize := range []int{0, 1} {
		f := &pipeFactory{}
		p, err := New(Options{Size: 4, MaxSize: 4, IdleTTL: time.Hour, IdleSize: idleSize}, f.create, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(f.close)
		t.Cleanup(p.Close)
		idle(t, p, 4)
		want := 4
		if idleSize == 1 {
			forceIdleFloor(p)
			// Simulate surplus entries expiring naturally, never close taken ones.
			p.mu.Lock()
			surplus := append([]*Entry(nil), p.idle[1:]...)
			p.mu.Unlock()
			for _, entry := range surplus {
				_ = entry.Conn.Close()
			}
			idle(t, p, 1)
			want = 1
		}
		p.mu.Lock()
		for _, entry := range p.idle {
			entry.refreshAt = time.Now().Add(-time.Second)
		}
		p.mu.Unlock()
		p.signal()
		deadline := time.Now().Add(2 * time.Second)
		for p.Stats().Renewed < uint64(want) && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if got := p.Stats().Renewed; got != uint64(want) || f.calls.Load() != int32(4+want) {
			t.Fatalf("idleSize=%d renewed=%d calls=%d, want %d renewals", idleSize, got, f.calls.Load(), want)
		}
		t.Logf("idleSize=%d: one controlled refresh cycle made %d replacement handshakes", idleSize, want)
		if idleSize == 1 {
			e := p.Take(context.Background())
			if e == nil {
				t.Fatal("idle floor left no ready connection")
			}
			defer e.Conn.Close()
			idle(t, p, 4)
		}
		p.Close()
		f.close()
	}
}
