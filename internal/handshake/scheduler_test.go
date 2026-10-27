package handshake

import (
	"context"
	"errors"
	"mygotunnel/internal/ingress"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	end := time.Now().Add(time.Second)
	for !f() {
		if time.Now().After(end) {
			t.Fatal("scheduler wait timed out")
		}
		time.Sleep(time.Millisecond)
	}
}
func TestForegroundOvertakesQueuedRenewalAndBoundedCancellation(t *testing.T) {
	o := Options{1000, 10, 1, 1, 2, time.Second}
	s := New(o)
	release, _, err := s.Acquire(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		bg      bool
		release func()
		err     error
	}
	done := make(chan result, 2)
	go func() { r, _, e := s.Acquire(context.Background(), true); done <- result{true, r, e} }()
	waitFor(t, func() bool { return s.Stats().Waiting == 1 })
	go func() { r, _, e := s.Acquire(context.Background(), false); done <- result{false, r, e} }()
	waitFor(t, func() bool { return s.Stats().Waiting == 2 })
	if _, _, e := s.Acquire(context.Background(), false); !errors.Is(e, ErrFull) {
		t.Fatal("unbounded queue", e)
	}
	release()
	release()
	a := <-done
	if a.err != nil || a.bg {
		t.Fatal("foreground lost priority", a.err)
	}
	a.release()
	b := <-done
	if b.err != nil || !b.bg {
		t.Fatal(b.err)
	}
	b.release()
	hold, _, _ := s.Acquire(context.Background(), false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, _, e := s.Acquire(ctx, false); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	hold()
	st := s.Stats()
	if st.Active != 0 || st.Waiting != 0 || st.Rejected != 1 || st.Canceled != 1 {
		t.Fatal(st)
	}
}
func TestBackgroundCannotOccupyForegroundReserve(t *testing.T) {
	s := New(Options{1000, 10, 3, 1, 10, time.Second})
	a, _, _ := s.Acquire(context.Background(), true)
	defer a()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		r, _, e := s.Acquire(ctx, true)
		if e == nil {
			r()
		}
		done <- e
	}()
	waitFor(t, func() bool { return s.Stats().Waiting == 1 })
	r, _, e := s.Acquire(context.Background(), false)
	if e != nil {
		t.Fatal(e)
	}
	r()
	cancel()
	if !errors.Is(<-done, context.Canceled) {
		t.Fatal("background ignored cancel")
	}
}
func TestDefaultPacingFitsEntranceBurst(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.1")}
	old := ingress.NewGuard(32, 20, 40)
	rejected := 0
	for range 48 {
		r, ok := old.Acquire(addr)
		if !ok {
			rejected++
		} else {
			r()
		}
	}
	if rejected == 0 {
		t.Fatal("fixture did not exceed entrance burst")
	}
	g := ingress.NewGuard(32, 20, 40)
	s := New(Defaults())
	var failures atomic.Int32
	var wg sync.WaitGroup
	for i := range 48 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, _, e := s.Acquire(context.Background(), i%5 == 0)
			if e != nil {
				failures.Add(1)
				return
			}
			defer r()
			gr, ok := g.Acquire(addr)
			if !ok {
				failures.Add(1)
				return
			}
			defer gr()
			time.Sleep(time.Millisecond)
		}()
	}
	wg.Wait()
	if failures.Load() != 0 || s.Stats().Active != 0 || s.Stats().Waiting != 0 {
		t.Fatal(failures.Load(), s.Stats())
	}
	t.Logf("48-attempt guard comparison: unpaced rejected=%d paced rejected=%d", rejected, failures.Load())
}

func TestValidateHandshakeOptions(t *testing.T) {
	good := Defaults()
	if good.Validate() != nil {
		t.Fatal("invalid defaults")
	}
	for _, o := range []Options{{}, {Rate: 1, Burst: 1, Concurrent: 1, Background: 2, Queue: 1, MaxWait: time.Second}, {Rate: 1, Burst: 1, Concurrent: 1, Background: 1, Queue: 5000, MaxWait: time.Second}} {
		if o.Validate() == nil {
			t.Fatal("invalid limits accepted", o)
		}
	}
}
