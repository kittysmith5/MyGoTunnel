package preconnect

import (
	"bufio"
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func idle(t *testing.T, p *Pool, n int) *Entry {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		count := len(p.idle)
		var e *Entry
		if count > 0 {
			e = p.idle[0]
		}
		p.mu.Unlock()
		if count == n {
			return e
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("pool did not reach expected idle count")
	return nil
}

type pipeFactory struct {
	mu    sync.Mutex
	peers []net.Conn
	calls atomic.Int32
}

func (f *pipeFactory) create(context.Context) (*Entry, error) {
	a, b := net.Pipe()
	f.mu.Lock()
	f.peers = append(f.peers, b)
	f.mu.Unlock()
	f.calls.Add(1)
	return &Entry{Conn: a, Reader: bufio.NewReader(a)}, nil
}
func (f *pipeFactory) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, peer := range f.peers {
		peer.Close()
	}
}
func (f *pipeFactory) peer(i int) net.Conn { f.mu.Lock(); defer f.mu.Unlock(); return f.peers[i] }

func TestPoolTransfersReaderAndDoesNotCloseTakenConnection(t *testing.T) {
	f := &pipeFactory{}
	defer f.close()
	p, err := New(Options{Size: 1}, f.create, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	original := idle(t, p, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	entry := p.Take(ctx)
	if entry != original || entry.Reader != original.Reader {
		t.Fatal("reader ownership was not preserved")
	}
	// Closing the pool must not close an already taken connection.
	p.Close()
	peer := f.peer(0)
	done := make(chan error, 1)
	go func() {
		peer.SetDeadline(time.Now().Add(time.Second))
		line, err := bufio.NewReader(peer).ReadString('\n')
		if err == nil && line != "CONNECT target:443\n" {
			err = io.ErrUnexpectedEOF
		}
		if err == nil {
			_, err = io.WriteString(peer, "OK\npayload\x00\n")
		}
		peer.Close()
		done <- err
	}()
	entry.Conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(entry.Conn, "CONNECT target:443\n"); err != nil {
		t.Fatal(err)
	}
	line, err := entry.Reader.ReadString('\n')
	if err != nil || line != "OK\n" {
		t.Fatal("response lost after stopping monitor")
	}
	data, err := io.ReadAll(entry.Reader)
	entry.Conn.Close()
	if err != nil || string(data) != "payload\x00\n" {
		t.Fatal("prefetched payload lost")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPoolExpiresAndDiscardsClosedConnections(t *testing.T) {
	for _, mode := range []string{"expiry", "EOF", "unexpected-data"} {
		t.Run(mode, func(t *testing.T) {
			f := &pipeFactory{}
			defer f.close()
			ttl := time.Second
			if mode == "expiry" {
				ttl = 80 * time.Millisecond
			}
			p, err := New(Options{Size: 1, IdleTTL: ttl}, f.create, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			original := idle(t, p, 1)
			switch mode {
			case "EOF":
				f.peer(0).Close()
			case "unexpected-data":
				go func() { io.WriteString(f.peer(0), "x") }()
			}
			select {
			case <-original.done:
			case <-time.After(2 * time.Second):
				t.Fatal("idle monitor failed to detect stale connection")
			}
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) {
				p.mu.Lock()
				different := len(p.idle) > 0 && p.idle[0] != original
				p.mu.Unlock()
				if different {
					break
				}
				time.Sleep(time.Millisecond)
			}
			entry := p.Take(context.Background())
			if entry == nil || entry == original {
				t.Fatal("stale connection reused or refill missing")
			}
			entry.Conn.Close()
		})
	}
}

func TestPoolRetryRecoveryAndCancellation(t *testing.T) {
	f := &pipeFactory{}
	defer f.close()
	var calls atomic.Int32
	p, err := New(Options{Size: 1, RetryMin: 10 * time.Millisecond, RetryMax: 20 * time.Millisecond}, func(ctx context.Context) (*Entry, error) {
		if calls.Add(1) == 1 {
			return nil, ErrUnsupported
		}
		return f.create(ctx)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	idle(t, p, 1)
	if calls.Load() < 2 {
		t.Fatal("unsupported negotiation did not recover")
	}
	p.Close()
	var failures atomic.Int32
	p, err = New(Options{Size: 2, RetryMin: 20 * time.Millisecond, RetryMax: 100 * time.Millisecond}, func(context.Context) (*Entry, error) { failures.Add(1); return nil, ErrBusy }, nil)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(230 * time.Millisecond)
	p.Close()
	count := failures.Load()
	if count < 1 || count > 8 {
		t.Fatalf("retry not bounded: %d", count)
	}
	time.Sleep(110 * time.Millisecond)
	if failures.Load() != count {
		t.Fatal("pool retried after close")
	}
	started := make(chan struct{}, 1)
	canceled := make(chan struct{}, 1)
	p, err = New(Options{Size: 1}, func(ctx context.Context) (*Entry, error) {
		started <- struct{}{}
		<-ctx.Done()
		canceled <- struct{}{}
		return nil, ctx.Err()
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("factory not started")
	}
	done := make(chan struct{})
	go func() { p.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pool close leaked blocked factory")
	}
	select {
	case <-canceled:
	default:
		t.Fatal("factory context not canceled")
	}
}

func TestPoolValidationAndEmptyTake(t *testing.T) {
	for _, options := range []Options{{Size: 0}, {Size: 33}, {Size: 1, IdleTTL: -1}, {Size: 1, RetryMin: time.Second, RetryMax: time.Millisecond}} {
		if _, err := New(options, func(context.Context) (*Entry, error) { return nil, ErrBusy }, nil); err == nil {
			t.Fatal("invalid options accepted")
		}
	}
	p, err := New(Options{Size: 1}, func(ctx context.Context) (*Entry, error) { <-ctx.Done(); return nil, ctx.Err() }, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	start := time.Now()
	if p.Take(context.Background()) != nil || time.Since(start) > 50*time.Millisecond {
		t.Fatal("empty pool blocked request")
	}
}
