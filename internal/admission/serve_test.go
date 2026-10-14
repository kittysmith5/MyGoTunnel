package admission

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func wait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not reach expected state")
	}
}

func TestServeRejectsOverflowAndRecovers(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	started, finished, overload := make(chan struct{}, 4), make(chan struct{}, 4), make(chan struct{}, 4)
	done := make(chan error, 1)
	go func() {
		done <- Serve(listener, 1, func(c net.Conn, release func()) {
			defer c.Close()
			started <- struct{}{}
			io.Copy(io.Discard, c)
			release()
			release() // Explicit and deferred release must be idempotent.
			finished <- struct{}{}
		}, func() { overload <- struct{}{} })
	}()
	first, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	wait(t, started)
	rejected, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer rejected.Close()
	wait(t, overload)
	rejected.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	_, err = rejected.Read(b[:])
	if err == nil {
		t.Fatal("overloaded connection remained open")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatal("overloaded connection was not closed promptly")
	}
	first.Close()
	wait(t, finished)
	recovered, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	wait(t, started)
	recovered.Close()
	wait(t, finished)
	listener.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestServeEstablishedConnectionsDoNotConsumeSetupSlots(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	started, finished := make(chan struct{}, 8), make(chan struct{}, 8)
	done := make(chan error, 1)
	go func() {
		done <- Serve(listener, 1, func(c net.Conn, release func()) {
			defer c.Close()
			release()
			started <- struct{}{}
			io.Copy(io.Discard, c)
			finished <- struct{}{}
		}, nil)
	}()
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for i := 0; i < 8; i++ {
		c, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		wait(t, started)
	}
	listener.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for _, c := range conns {
		c.Close()
	}
	for range conns {
		wait(t, finished)
	}
}

type errorListener struct {
	err       error
	temporary bool
	calls     int
}

func (l *errorListener) Accept() (net.Conn, error) {
	l.calls++
	if l.temporary && l.calls > 1 {
		return nil, net.ErrClosed
	}
	return nil, l.err
}
func (*errorListener) Close() error   { return nil }
func (*errorListener) Addr() net.Addr { return &net.TCPAddr{} }

type temporaryError struct{}

func (temporaryError) Error() string   { return "temporary test error" }
func (temporaryError) Temporary() bool { return true }
func (temporaryError) Timeout() bool   { return false }

func TestServeAcceptErrorsAndValidation(t *testing.T) {
	for _, limit := range []int{0, -1} {
		if err := Serve(nil, limit, nil, nil); err == nil {
			t.Fatal("invalid limit accepted")
		}
	}
	fatal := errors.New("permanent accept error")
	listener := &errorListener{err: fatal}
	if err := Serve(listener, 1, nil, nil); !errors.Is(err, fatal) || listener.calls != 1 {
		t.Fatal("permanent accept error retried or hidden")
	}
	listener = &errorListener{err: temporaryError{}, temporary: true}
	start := time.Now()
	if err := Serve(listener, 1, nil, nil); err != nil || listener.calls != 2 {
		t.Fatal("temporary accept error did not recover")
	}
	if time.Since(start) < 5*time.Millisecond {
		t.Fatal("temporary accept failure caused tight retry loop")
	}
}

func TestPermitReacquiresAndTotalConnectionsRemainBounded(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	started := make(chan *Permit, 2)
	overload := make(chan struct{}, 2)
	finished := make(chan struct{}, 2)
	done := make(chan error, 1)
	go func() {
		done <- ServeWithPermit(listener, 1, 1, func(c net.Conn, p *Permit) {
			defer c.Close()
			p.Release()
			started <- p
			io.Copy(io.Discard, c)
			finished <- struct{}{}
		}, func() { overload <- struct{}{} })
	}()
	first, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	var permit *Permit
	select {
	case permit = <-started:
	case <-time.After(time.Second):
		t.Fatal("handler not started")
	}
	if !permit.TryAcquire() {
		t.Fatal("released setup permit could not reacquire")
	}
	permit.Release()
	second, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	wait(t, overload)
	first.Close()
	wait(t, finished)
	// The total slot is released by Serve after the handler returns.
	listener.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := ServeWithPermit(nil, 1, -1, nil, nil); err == nil {
		t.Fatal("negative total limit accepted")
	}
}

func TestResourceCountersTrackPermitAndConnectionLifetime(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	counters := &Counters{}
	started := make(chan *Permit, 2)
	rejected := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- ServeWithMetrics(listener, 1, 2, func(c net.Conn, p *Permit) { defer c.Close(); started <- p; io.Copy(io.Discard, c) }, func() { rejected <- struct{}{} }, counters)
	}()
	connect := func() net.Conn {
		c, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	waitCounts := func(open, setup int64) {
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			if counters.Open.Load() == open && counters.Setup.Load() == setup {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatalf("counts open=%d setup=%d", counters.Open.Load(), counters.Setup.Load())
	}
	a := connect()
	defer a.Close()
	first := <-started
	waitCounts(1, 1)
	first.Release()
	first.Release()
	waitCounts(1, 0)
	b := connect()
	defer b.Close()
	<-started
	waitCounts(2, 1)
	c := connect()
	defer c.Close()
	wait(t, rejected)
	if counters.Rejected.Load() != 1 {
		t.Fatal("rejected counter missing")
	}
	if first.TryAcquire() {
		t.Fatal("reacquired full setup slot")
	}
	b.Close()
	waitCounts(1, 0)
	if !first.TryAcquire() {
		t.Fatal("reacquire failed")
	}
	waitCounts(1, 1)
	a.Close()
	waitCounts(0, 0)
	listener.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestGracefulShutdown(t *testing.T) {
	for _, force := range []bool{false, true} {
		t.Run(map[bool]string{false: "drain", true: "force"}[force], func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started := make(chan struct{})
			done := make(chan error, 1)
			metrics := &Counters{}
			go func() {
				done <- ServeContext(ctx, 100*time.Millisecond, ln, 1, 1, func(c net.Conn, p *Permit) { defer c.Close(); p.Release(); close(started); io.Copy(c, c) }, nil, metrics)
			}()
			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			wait(t, started)
			cancel()
			if !force {
				c.SetDeadline(time.Now().Add(time.Second))
				if _, err := c.Write([]byte("ok")); err != nil {
					t.Fatal(err)
				}
				b := make([]byte, 2)
				if _, err := io.ReadFull(c, b); err != nil || string(b) != "ok" {
					t.Fatalf("drain failed: %q %v", b, err)
				}
				c.Close()
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("shutdown stuck")
			}
			if metrics.Open.Load() != 0 || metrics.Setup.Load() != 0 {
				t.Fatal("handlers not joined")
			}
			if force {
				c.SetReadDeadline(time.Now().Add(time.Second))
				var b [1]byte
				if _, err := c.Read(b[:]); err == nil {
					t.Fatal("connection not closed")
				}
			}
		})
	}
}
