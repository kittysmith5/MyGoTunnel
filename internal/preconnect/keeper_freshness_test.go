package preconnect

import (
	"bufio"
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

func TestShrinkingPoolRenewsOneKeeperBeforeSurplusExpires(t *testing.T) {
	for _, idlePolicy := range []bool{false, true} {
		t.Run(map[bool]string{false: "adaptive_floor", true: "idle_floor"}[idlePolicy], func(t *testing.T) {
			f := &pipeFactory{}
			defer f.close()
			var calls atomic.Int32
			started := make(chan struct{}, 1)
			opts := Options{Size: 1, MaxSize: 3, IdleTTL: time.Hour}
			if idlePolicy {
				opts.Size, opts.IdleSize = 2, 1
			}
			p, err := New(opts, func(ctx context.Context) (*Entry, error) {
				if calls.Add(1) > 2 {
					select {
					case started <- struct{}{}:
					default:
					}
					select {
					case <-time.After(150 * time.Millisecond):
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				return f.create(ctx)
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			if !idlePolicy {
				idle(t, p, 1)
				p.mu.Lock()
				p.target = 2 // previously expanded adaptive pool
				p.mu.Unlock()
				p.signal()
			}
			idle(t, p, 2)
			p.mu.Lock()
			p.target = 1
			p.lastDemand = time.Now().Add(-time.Hour)
			now := time.Now()
			for i, entry := range p.idle {
				entry.refreshAt = now.Add(-time.Second)
				entry.expires = now.Add(time.Duration(400+40*i) * time.Millisecond)
				if err := entry.Conn.SetReadDeadline(entry.expires); err != nil {
					t.Fatal(err)
				}
			}
			p.mu.Unlock()
			p.signal()
			select {
			case <-started:
			case <-time.After(250 * time.Millisecond):
				t.Fatal("keeper renewal waited for surplus expiry")
			}
			// Cross both original expiries: a healthy renewal must already protect
			// the idle floor, without renewing every surplus connection.
			for time.Now().Before(now.Add(650 * time.Millisecond)) {
				s := p.Stats()
				if s.Idle == 0 || s.Idle+s.Filling > opts.MaxSize {
					t.Fatalf("keeper/capacity lost: %+v", s)
				}
				time.Sleep(5 * time.Millisecond)
			}
			if s := p.Stats(); s.Idle != 1 || s.Renewed != 1 || calls.Load() != 3 {
				t.Fatalf("surplus was renewed unnecessarily: stats=%+v calls=%d", s, calls.Load())
			}
		})
	}
}

func TestTakeUsesFreshReadyChannelAheadOfSilentOldChannel(t *testing.T) {
	f := &pipeFactory{}
	defer f.close()
	var calls atomic.Int32
	allowSecond := make(chan struct{})
	p, err := New(Options{Size: 2, MaxSize: 2}, func(ctx context.Context) (*Entry, error) {
		n := calls.Add(1)
		if n > 2 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		if n == 2 {
			select {
			case <-allowSecond:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		entry, err := f.create(ctx)
		if err == nil && n == 2 {
			go func() {
				reader := bufio.NewReader(f.peer(1))
				if line, err := reader.ReadString('\n'); err == nil && line == "CONNECT target:443\n" {
					_, _ = io.WriteString(f.peer(1), "ACK\nOK\n")
				}
			}()
		}
		return entry, err
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	idle(t, p, 1)
	close(allowSecond)
	idle(t, p, 2)
	entry := p.Take(context.Background())
	if entry == nil {
		t.Fatal("no ready channel")
	}
	defer entry.Conn.Close()
	if err := entry.Conn.SetDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(entry.Conn, "CONNECT target:443\n"); err != nil {
		t.Fatalf("selected the old silent connection: %v", err)
	}
	for _, want := range []string{"ACK\n", "OK\n"} {
		if got, err := entry.Reader.ReadString('\n'); err != nil || got != want {
			t.Fatalf("fresh response=%q error=%v", got, err)
		}
	}
}
