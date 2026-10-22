package admission

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"mygotunnel/internal/relay"
)

func TestGraceExpiryAbortsBothSidesOfHalfClosedRelay(t *testing.T) {
	for _, uploadEOF := range []bool{true, false} {
		t.Run(map[bool]string{true: "upload_eof", false: "download_eof"}[uploadEOF], func(t *testing.T) {
			targetListener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer targetListener.Close()
			target, err := net.Dial("tcp4", targetListener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			peer, err := targetListener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			const grace = 30 * time.Millisecond
			done := make(chan error, 1)
			results := make(chan relay.Result, 1)
			metrics := &Counters{}
			go func() {
				done <- ServeContext(ctx, grace, listener, 2, 2, func(conn net.Conn, permit *Permit) {
					defer conn.Close()
					defer target.Close()
					permit.Release()
					results <- relay.CopyBidirectionalContext(permit.AbortContext(), conn, conn, target, target)
				}, nil, metrics)
			}()
			app, err := net.Dial("tcp4", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer app.Close()
			t.Cleanup(func() { cancel(); app.Close(); peer.Close() })
			if err := app.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := peer.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if uploadEOF {
				if err := app.(*net.TCPConn).CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadAll(peer); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := peer.(*net.TCPConn).CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadAll(app); err != nil {
					t.Fatal(err)
				}
			}
			started := time.Now()
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("grace expiry did not abort reverse source read")
			}
			if elapsed := time.Since(started); elapsed < grace/2 {
				t.Fatalf("process cancellation skipped grace: %v", elapsed)
			}
			result := <-results
			wantDirection := map[bool]string{true: "down", false: "up"}[uploadEOF]
			if result.Err == nil || result.FailureDirection != wantDirection || result.FailurePhase != "copy" {
				t.Fatalf("root direction after half-close abort: %+v", result)
			}
			if metrics.Open.Load() != 0 || metrics.Setup.Load() != 0 {
				t.Fatal("force-aborted relay retained admission counters")
			}
		})
	}
}
