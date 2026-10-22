package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mygotunnel/internal/preconnect"
	"mygotunnel/internal/tunnel"
)

func TestPreparedFreshChannelAvoidsSilentOlderACKWait(t *testing.T) {
	var count atomic.Int32
	second := make(chan struct{})
	var mu sync.Mutex
	var peers []net.Conn
	var workers sync.WaitGroup
	pool, err := preconnect.New(preconnect.Options{Size: 2, MaxSize: 2}, func(ctx context.Context) (*preconnect.Entry, error) {
		n := count.Add(1)
		if n > 2 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		if n == 2 {
			select {
			case <-second:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		a, b := net.Pipe()
		mu.Lock()
		peers = append(peers, b)
		mu.Unlock()
		workers.Add(1)
		go func() {
			defer workers.Done()
			reader := bufio.NewReader(b)
			if _, err := tunnel.ReadLine(reader); err != nil {
				return
			}
			if n == 2 {
				_, _ = io.WriteString(b, "ACK\nOK\n")
			} else {
				_, _ = io.Copy(io.Discard, reader)
			}
		}()
		return &preconnect.Entry{Conn: a, Reader: bufio.NewReader(a), CommandACK: true}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		pool.Close()
		mu.Lock()
		for _, peer := range peers {
			_ = peer.Close()
		}
		mu.Unlock()
		workers.Wait()
	}()
	wait := func(n int) {
		t.Helper()
		until := time.Now().Add(time.Second)
		for pool.IdleCount() != n && time.Now().Before(until) {
			time.Sleep(time.Millisecond)
		}
		if pool.IdleCount() != n {
			t.Fatalf("pool not ready: want %d", n)
		}
	}
	wait(1)
	close(second)
	wait(2)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	fresh := pool.Take(ctx)
	if fresh == nil {
		t.Fatal("missing fresh standby")
	}
	defer closeUnusedRemote(fresh.Conn)
	started := time.Now()
	response, err := exchangePrepared(ctx, fresh, "target.invalid:443", false, &remoteSession{})
	if err != nil || response != "OK" {
		t.Fatalf("selected silent older channel ahead of healthy fresh channel: %q, %v", response, err)
	}
	t.Logf("fresh prepared command completed: %v", time.Since(started))

	// Selection does not claim that older channels are healthy or discard them
	// prematurely. Their command ACK still observes the parent's own budget.
	oldCtx, oldCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer oldCancel()
	old := pool.Take(oldCtx)
	if old == nil {
		t.Fatal("older unused standby was lost")
	}
	defer closeUnusedRemote(old.Conn)
	if _, err := exchangePrepared(oldCtx, old, "target.invalid:443", false, &remoteSession{}); err == nil {
		t.Fatal("silent channel bypassed ACK deadline")
	}
}
