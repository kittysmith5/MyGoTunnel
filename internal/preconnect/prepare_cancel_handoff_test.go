package preconnect

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Cancellation may be visible before a scheduled AfterFunc starts. Hold that
// scheduling edge until the setup has returned, without changing TLS I/O.
type delayedPrepareCancellation struct {
	context.Context
	deliver <-chan struct{}
	workers sync.WaitGroup
}

func (c *delayedPrepareCancellation) Value(any) any { return nil }

func (c *delayedPrepareCancellation) AfterFunc(f func()) func() bool {
	var state atomic.Int32 // pending=0, started=1, stopped=2
	stopped := make(chan struct{})
	c.workers.Add(1)
	go func() {
		defer c.workers.Done()
		select {
		case <-c.Done():
		case <-stopped:
			return
		}
		select {
		case <-c.deliver:
		case <-stopped:
			return
		}
		if state.CompareAndSwap(0, 1) {
			f()
		}
	}()
	return func() bool {
		if !state.CompareAndSwap(0, 2) {
			return false
		}
		close(stopped)
		return true
	}
}

func TestPrepareDoesNotHandoffAfterCanceledReady(t *testing.T) {
	for _, ack := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "ack"}[ack], func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			deliver := make(chan struct{})
			ctx := &delayedPrepareCancellation{Context: parent, deliver: deliver}
			defer func() { close(deliver); ctx.workers.Wait() }()
			_, cfg := newPrepareACKServer(t, func(_ int, _ string, conn net.Conn, _ *bufio.Reader) error {
				cancel()
				response := "OK\nREADY\n"
				if ack {
					response = "OK\nREADY ACK\n"
				}
				_, err := io.WriteString(conn, response)
				return err
			})
			type result struct {
				entry *Entry
				err   error
			}
			done := make(chan result, 1)
			go func() {
				entry, err := prepare(ctx, cfg, ack)
				done <- result{entry, err}
			}()
			select {
			case got := <-done:
				if got.entry != nil {
					got.entry.Conn.Close()
				}
				if got.entry != nil || !errors.Is(got.err, context.Canceled) {
					t.Fatalf("canceled READY transferred ownership: entry=%v error=%v", got.entry, got.err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("preparation did not reject canceled READY")
			}
		})
	}
}
