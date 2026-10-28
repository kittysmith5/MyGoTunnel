package admission

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type mergeAcceptResult struct {
	conn net.Conn
	err  error
}

type mergeTestListener struct {
	incoming chan mergeAcceptResult
	accepted chan struct{}
	done     chan struct{}
	once     sync.Once
	closes   atomic.Int32
	address  net.Addr
}

func newMergeTestListener(port int) *mergeTestListener {
	return &mergeTestListener{
		incoming: make(chan mergeAcceptResult), accepted: make(chan struct{}, 16),
		done: make(chan struct{}), address: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
	}
}

func (l *mergeTestListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, net.ErrClosed
	case result := <-l.incoming:
		l.accepted <- struct{}{}
		return result.conn, result.err
	}
}

func (l *mergeTestListener) Close() error {
	l.closes.Add(1)
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *mergeTestListener) Addr() net.Addr { return l.address }

type mergeTestConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *mergeTestConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

func newMergeTestConn(t *testing.T) *mergeTestConn {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	return &mergeTestConn{Conn: server}
}

func deliverMergeResult(t *testing.T, listener *mergeTestListener, result mergeAcceptResult) {
	t.Helper()
	select {
	case listener.incoming <- result:
	case <-time.After(3 * time.Second):
		t.Fatal("child Accept did not receive result")
	}
	select {
	case <-listener.accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("child Accept did not return result")
	}
}

func acceptMerged(t *testing.T, listener net.Listener) mergeAcceptResult {
	t.Helper()
	result := make(chan mergeAcceptResult, 1)
	go func() {
		conn, err := listener.Accept()
		result <- mergeAcceptResult{conn, err}
	}()
	select {
	case got := <-result:
		return got
	case <-time.After(3 * time.Second):
		t.Fatal("merged Accept remained blocked")
		return mergeAcceptResult{}
	}
}

func closeMerged(t *testing.T, listener net.Listener) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- listener.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("merged Close: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("merged Close did not join workers")
	}
}

func TestMergeListenersValidatesInputsWithoutTakingOwnership(t *testing.T) {
	if _, err := MergeListeners(); err == nil {
		t.Fatal("accepted zero listeners")
	}
	child := newMergeTestListener(1)
	if _, err := MergeListeners(child, nil); err == nil {
		t.Fatal("accepted nil listener")
	}
	if child.closes.Load() != 0 {
		t.Fatal("failed constructor took ownership")
	}
}

func TestMergedListenerAcceptsIndependentChildren(t *testing.T) {
	first, second := newMergeTestListener(1), newMergeTestListener(2)
	listener, err := MergeListeners(first, second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if listener.Addr() != first.Addr() {
		t.Fatal("Addr did not preserve first child address")
	}
	// The first child's Accept remains blocked. The second must still deliver.
	secondConn := newMergeTestConn(t)
	deliverMergeResult(t, second, mergeAcceptResult{conn: secondConn})
	got := acceptMerged(t, listener)
	if got.err != nil || got.conn != secondConn {
		t.Fatalf("second child starved: %v", got.err)
	}
	_ = got.conn.Close()
	// Both workers can now hold one independent arrival before the caller
	// accepts either of them; there is no shared child-Accept lock.
	firstConn, nextSecondConn := newMergeTestConn(t), newMergeTestConn(t)
	deliverMergeResult(t, first, mergeAcceptResult{conn: firstConn})
	deliverMergeResult(t, second, mergeAcceptResult{conn: nextSecondConn})
	seen := make(map[net.Conn]bool)
	for range 2 {
		got = acceptMerged(t, listener)
		if got.err != nil || seen[got.conn] || got.conn != firstConn && got.conn != nextSecondConn {
			t.Fatalf("invalid independent arrival: %v", got.err)
		}
		seen[got.conn] = true
		_ = got.conn.Close()
	}
}

func TestMergedCloseReclaimsPendingConnectionsAndJoinsWorkers(t *testing.T) {
	first, second := newMergeTestListener(1), newMergeTestListener(2)
	listener, err := MergeListeners(first, second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	pending := newMergeTestConn(t)
	deliverMergeResult(t, first, mergeAcceptResult{conn: pending})
	closeMerged(t, listener)
	closeMerged(t, listener)
	if pending.closes.Load() != 1 || first.closes.Load() != 1 || second.closes.Load() != 1 {
		t.Fatalf("close counts conn=%d first=%d second=%d", pending.closes.Load(), first.closes.Load(), second.closes.Load())
	}
	got := acceptMerged(t, listener)
	if got.conn != nil || !errors.Is(got.err, net.ErrClosed) {
		t.Fatalf("Accept after Close: %v", got.err)
	}
	select {
	case <-listener.(*mergedListener).stopped:
	default:
		t.Fatal("Close returned before workers stopped")
	}
}

func TestMergedCloseUnblocksAcceptAndKeepsReturnedConnection(t *testing.T) {
	child := newMergeTestListener(1)
	listener, err := MergeListeners(child)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	conn := newMergeTestConn(t)
	deliverMergeResult(t, child, mergeAcceptResult{conn: conn})
	got := acceptMerged(t, listener)
	if got.err != nil || got.conn != conn {
		t.Fatalf("Accept: %v", got.err)
	}
	blocked := make(chan mergeAcceptResult, 1)
	go func() {
		conn, err := listener.Accept()
		blocked <- mergeAcceptResult{conn, err}
	}()
	closeMerged(t, listener)
	select {
	case result := <-blocked:
		if result.conn != nil || !errors.Is(result.err, net.ErrClosed) {
			t.Fatalf("blocked Accept: %v", result.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not unblock Accept")
	}
	if conn.closes.Load() != 0 {
		t.Fatal("Close reclaimed a connection already returned to caller")
	}
	_ = conn.Close()
}

func TestMergedChildFailureStopsAllChildrenAndPreservesRootError(t *testing.T) {
	fatal := errors.New("test child failure")
	for _, failure := range []error{fatal, net.ErrClosed} {
		t.Run(failure.Error(), func(t *testing.T) {
			first, second := newMergeTestListener(1), newMergeTestListener(2)
			listener, err := MergeListeners(first, second)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			pending := newMergeTestConn(t)
			deliverMergeResult(t, first, mergeAcceptResult{conn: pending})
			deliverMergeResult(t, second, mergeAcceptResult{err: failure})
			select {
			case <-listener.(*mergedListener).done:
			case <-time.After(3 * time.Second):
				t.Fatal("child error did not terminate merged listener")
			}
			got := acceptMerged(t, listener)
			if got.conn != nil || !errors.Is(got.err, failure) {
				t.Fatalf("child root error lost: %v", got.err)
			}
			closeMerged(t, listener)
			if pending.closes.Load() != 1 || first.closes.Load() != 1 || second.closes.Load() != 1 {
				t.Fatal("failure did not reclaim pending connections and children exactly once")
			}
		})
	}
}

func mergeTemporaryResourceError() error {
	return &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept4", syscall.EMFILE)}
}

func TestMergedTemporaryAcceptRecoversThroughServe(t *testing.T) {
	first, second := newMergeTestListener(1), newMergeTestListener(2)
	listener, err := MergeListeners(first, second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	handled := make(chan net.Conn, 2)
	metrics := &Counters{}
	go func() {
		finished <- ServeContext(ctx, 0, listener, 2, 4, func(c net.Conn, p *Permit) {
			p.Release()
			handled <- c
			_ = c.Close()
		}, nil, metrics)
	}()
	t.Cleanup(func() {
		cancel()
		closeMerged(t, listener)
		select {
		case err := <-finished:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("serve did not stop after resource error recovery")
		}
		if metrics.Open.Load() != 0 || metrics.Setup.Load() != 0 {
			t.Error("resource error recovery leaked admission permits")
		}
	})
	deliverMergeResult(t, first, mergeAcceptResult{err: mergeTemporaryResourceError()})
	for _, child := range []*mergeTestListener{second, first} {
		conn := newMergeTestConn(t)
		deliverMergeResult(t, child, mergeAcceptResult{conn: conn})
		select {
		case got := <-handled:
			if got != conn {
				t.Fatal("wrong recovered connection")
			}
		case <-time.After(time.Second):
			t.Fatal("temporary failure stopped either transport")
		}
	}
	if first.closes.Load() != 0 || second.closes.Load() != 0 {
		t.Fatal("temporary failure closed a child listener")
	}
}

func TestMergedPersistentTemporaryAcceptKeepsOtherChildAvailable(t *testing.T) {
	first, second := newMergeTestListener(1), newMergeTestListener(2)
	listener, err := MergeListeners(first, second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeMerged(t, listener) })
	started := time.Now()
	for range 6 {
		deliverMergeResult(t, first, mergeAcceptResult{err: mergeTemporaryResourceError()})
		conn := newMergeTestConn(t)
		deliverMergeResult(t, second, mergeAcceptResult{conn: conn})
		got := acceptMerged(t, listener)
		if got.err != nil || got.conn != conn {
			t.Fatalf("healthy transport unavailable during backoff: %v", got.err)
		}
		_ = conn.Close()
	}
	// Six consecutive failures require at least the first five backoff waits.
	if time.Since(started) < 155*time.Millisecond {
		t.Fatal("persistent resource failure caused immediate retries")
	}
}

func TestMergedCloseInterruptsMaximumTemporaryBackoff(t *testing.T) {
	first, second := newMergeTestListener(1), newMergeTestListener(2)
	listener, err := MergeListeners(first, second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	// The ninth failure enters the capped one-second wait. Close must not wait
	// for that timer to expire, and must join both child workers.
	for range 9 {
		deliverMergeResult(t, first, mergeAcceptResult{err: mergeTemporaryResourceError()})
	}
	finished := make(chan error, 1)
	go func() { finished <- listener.Close() }()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Close did not interrupt temporary accept backoff")
	}
	if first.closes.Load() != 1 || second.closes.Load() != 1 {
		t.Fatal("Close did not reclaim both child listeners")
	}
	if got := acceptMerged(t, listener); !errors.Is(got.err, net.ErrClosed) {
		t.Fatalf("Accept after interrupting backoff: %v", got.err)
	}
}

func TestMergedListenerConcurrentCloseAndDelivery(t *testing.T) {
	for range 100 {
		first, second := newMergeTestListener(1), newMergeTestListener(2)
		listener, err := MergeListeners(first, second)
		if err != nil {
			t.Fatal(err)
		}
		conns := []*mergeTestConn{newMergeTestConn(t), newMergeTestConn(t)}
		children := []*mergeTestListener{first, second}
		start := make(chan struct{})
		var workers sync.WaitGroup
		for i, child := range children {
			workers.Add(1)
			go func(child *mergeTestListener, conn *mergeTestConn) {
				defer workers.Done()
				<-start
				select {
				case child.incoming <- mergeAcceptResult{conn: conn}:
				case <-child.done:
					_ = conn.Close()
				}
			}(child, conns[i])
		}
		for range 2 {
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-start
				conn, err := listener.Accept()
				if conn != nil {
					_ = conn.Close()
				} else if !errors.Is(err, net.ErrClosed) {
					t.Errorf("concurrent Accept: %v", err)
				}
			}()
		}
		for range 4 {
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-start
				if err := listener.Close(); err != nil {
					t.Errorf("concurrent Close: %v", err)
				}
			}()
		}
		close(start)
		done := make(chan struct{})
		go func() { workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("concurrent delivery or shutdown leaked a worker")
		}
		if first.closes.Load() != 1 || second.closes.Load() != 1 {
			t.Fatal("concurrent Close closed a child more than once")
		}
		for _, conn := range conns {
			if conn.closes.Load() != 1 {
				t.Fatalf("connection ownership lost during shutdown: closes=%d", conn.closes.Load())
			}
		}
	}
}
