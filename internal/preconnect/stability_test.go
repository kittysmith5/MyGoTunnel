package preconnect

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetryAdvancesOncePerCooldown(t *testing.T) {
	p := &Pool{opts: Options{RetryMin: time.Second, RetryMax: 8 * time.Second}, filling: 8}
	for i := 0; i < 8; i++ {
		p.filling--
		var e error
		if i < 7 {
			e = ErrBusy
		}
		p.completeBatchLocked(e)
	}
	if p.retry != time.Second {
		t.Fatalf("parallel failures multiplied backoff: %v", p.retry)
	}
	p.batchFailed = false
	p.nextRetry = time.Time{}
	p.filling = 2
	p.filling--
	p.completeBatchLocked(ErrBusy)
	p.filling--
	p.completeBatchLocked(nil)
	if p.retry != 2*time.Second {
		t.Fatal("partial success cleared failure", p.retry)
	}
	p.batchFailed = false
	p.nextRetry = time.Time{}
	p.filling = 1
	p.filling--
	p.completeBatchLocked(nil)
	if p.retry != 0 || !p.nextRetry.IsZero() {
		t.Fatal("healthy batch did not recover")
	}
}
func TestFailedReplacementKeepsOldReady(t *testing.T) {
	f := &pipeFactory{}
	defer f.close()
	attempt := make(chan struct{}, 1)
	p, e := New(Options{Size: 1, MaxSize: 2, IdleTTL: 10 * time.Second, RetryMin: time.Second, RetryMax: time.Second}, func(ctx context.Context) (*Entry, error) {
		if f.calls.Load() > 0 {
			attempt <- struct{}{}
			return nil, errors.New("temporary")
		}
		return f.create(ctx)
	}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	old := idle(t, p, 1)
	p.mu.Lock()
	old.refreshAt = time.Now().Add(-time.Second)
	p.mu.Unlock()
	p.signal()
	select {
	case <-attempt:
	case <-time.After(time.Second):
		t.Fatal("renewal not attempted")
	}
	got := p.Take(context.Background())
	if got != old {
		t.Fatal("failed replacement discarded usable connection")
	}
	got.Conn.Close()
}
func TestReplacementDoesNotCloseTakenOld(t *testing.T) {
	f := &pipeFactory{}
	defer f.close()
	started := make(chan struct{})
	release := make(chan struct{})
	p, e := New(Options{Size: 1, MaxSize: 2, IdleTTL: 10 * time.Second}, func(ctx context.Context) (*Entry, error) {
		if f.calls.Load() > 0 {
			select {
			case <-started:
			default:
				close(started)
			}
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return f.create(ctx)
	}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	old := idle(t, p, 1)
	p.mu.Lock()
	old.refreshAt = time.Now().Add(-time.Second)
	p.mu.Unlock()
	p.signal()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("no renewal")
	}
	taken := p.Take(context.Background())
	if taken != old {
		t.Fatal("old entry unavailable")
	}
	close(release)
	idle(t, p, 2)
	p.Close()
	done := make(chan error, 1)
	go func() { b := make([]byte, 1); _, e := io.ReadFull(f.peer(0), b); done <- e }()
	taken.Conn.SetDeadline(time.Now().Add(time.Second))
	if _, e := taken.Conn.Write([]byte{1}); e != nil {
		t.Fatal("taken connection closed", e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	taken.Conn.Close()
}
func TestRenewalJitterAndHardCap(t *testing.T) {
	f := &pipeFactory{}
	defer f.close()
	p, e := New(Options{Size: 2, MaxSize: 2, IdleTTL: 500 * time.Millisecond}, f.create, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	idle(t, p, 2)
	p.mu.Lock()
	for _, entry := range p.idle {
		left := time.Until(entry.expires)
		if left < 350*time.Millisecond || left > 500*time.Millisecond || !entry.refreshAt.Before(entry.expires) {
			t.Fatal("invalid expiry bounds")
		}
	}
	p.mu.Unlock()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s := p.Stats()
		if s.Idle+s.Filling > 2 {
			t.Fatal("capacity exceeded", s)
		}
		if s.Renewed > 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no proactive replacement")
}
func TestCloseDuringReplacement(t *testing.T) {
	f := &pipeFactory{}
	defer f.close()
	started := make(chan struct{})
	p, e := New(Options{Size: 1, MaxSize: 2}, func(ctx context.Context) (*Entry, error) {
		if f.calls.Load() > 0 {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return f.create(ctx)
	}, nil)
	if e != nil {
		t.Fatal(e)
	}
	old := idle(t, p, 1)
	p.mu.Lock()
	old.refreshAt = time.Now().Add(-time.Second)
	p.mu.Unlock()
	p.signal()
	<-started
	done := make(chan struct{})
	go func() { p.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("replacement leaked on Close")
	}
}

func TestMixedBatchDoesNotRetryImmediately(t *testing.T) {
	f := &pipeFactory{}
	defer f.close()
	var calls atomic.Int32
	p, e := New(Options{Size: 8, RetryMin: time.Second, RetryMax: 8 * time.Second}, func(ctx context.Context) (*Entry, error) {
		if calls.Add(1) <= 7 {
			return nil, ErrBusy
		}
		return f.create(ctx)
	}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if calls.Load() == 8 && p.Stats().Filling == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(30 * time.Millisecond)
	if calls.Load() != 8 || p.Stats().Retry != time.Second || p.Stats().Idle != 1 {
		t.Fatalf("mixed batch retried or multiplied backoff: calls=%d stats=%+v", calls.Load(), p.Stats())
	}
}

func TestSlowFillDoesNotBlockDemandRefill(t *testing.T) {
	f := &pipeFactory{}
	defer f.close()
	var calls atomic.Int32
	slow := make(chan struct{})
	p, err := New(Options{Size: 2, MaxSize: 2}, func(ctx context.Context) (*Entry, error) {
		if calls.Add(1) == 1 {
			close(slow)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return f.create(ctx)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	<-slow
	idle(t, p, 1)
	entry := p.Take(context.Background())
	if entry == nil {
		t.Fatal("ready connection not available")
	}
	defer entry.Conn.Close()
	idle(t, p, 1)
	if calls.Load() < 3 {
		t.Fatal("slow handshake blocked refill")
	}
	if s := p.Stats(); s.Idle+s.Filling > 2 {
		t.Fatal("capacity exceeded", s)
	}
}

func TestFailureCooldownDoesNotWaitForSlowWorker(t *testing.T) {
	f := &pipeFactory{}
	defer f.close()
	var calls atomic.Int32
	p, err := New(Options{Size: 2, MaxSize: 2, RetryMin: 20 * time.Millisecond, RetryMax: 20 * time.Millisecond}, func(ctx context.Context) (*Entry, error) {
		switch calls.Add(1) {
		case 1:
			<-ctx.Done()
			return nil, ctx.Err()
		case 2:
			return nil, ErrBusy
		default:
			return f.create(ctx)
		}
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	idle(t, p, 1)
	if calls.Load() < 3 {
		t.Fatal("cooldown still blocked by slow worker")
	}
}
