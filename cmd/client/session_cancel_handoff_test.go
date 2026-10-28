package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/preconnect"
	"mygotunnel/internal/tunnel"
)

// Delay the cancellation close after a complete result is already readable.
// This selects a valid scheduling order without depending on TLS packet timing.
type cancellationHandoffConn struct {
	net.Conn
	cancel         context.CancelFunc
	closing, allow chan struct{}
	once           sync.Once
	err            error
}

func (c *cancellationHandoffConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if bytes.Contains(p[:n], []byte("OK\n")) {
		c.cancel()
		<-c.closing
	}
	return n, err
}

func (c *cancellationHandoffConn) Close() error {
	c.once.Do(func() {
		close(c.closing)
		<-c.allow
		c.err = c.Conn.Close()
	})
	return c.err
}

func TestTLSPreparedCancellationJoinsBeforeHandoff(t *testing.T) {
	for _, udp := range []bool{false, true} {
		t.Run(map[bool]string{false: "tcp", true: "udp"}[udp], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a, b := net.Pipe()
			wrapped := &cancellationHandoffConn{Conn: a, cancel: cancel, closing: make(chan struct{}), allow: make(chan struct{})}
			var releaseOnce sync.Once
			releaseClose := func() { releaseOnce.Do(func() { close(wrapped.allow) }) }
			var calls atomic.Int32
			pool, err := preconnect.New(preconnect.Options{Size: 1}, func(ctx context.Context) (*preconnect.Entry, error) {
				if calls.Add(1) != 1 {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return &preconnect.Entry{Conn: wrapped, Reader: bufio.NewReader(wrapped)}, nil
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { releaseClose(); a.Close(); b.Close(); pool.Close() })
			until := time.Now().Add(time.Second)
			for pool.IdleCount() != 1 && time.Now().Before(until) {
				time.Sleep(time.Millisecond)
			}
			if pool.IdleCount() != 1 {
				t.Fatal("pool did not become ready")
			}
			peerDone := make(chan struct{})
			go func() {
				defer close(peerDone)
				defer b.Close()
				b.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := tunnel.ReadLine(bufio.NewReader(b)); err == nil {
					_, _ = io.WriteString(b, "OK\n")
				}
			}()
			type result struct {
				session *remoteSession
				err     error
			}
			done := make(chan result, 1)
			go func() {
				session, err := openRemoteCommand(ctx, &config.ClientConfig{}, "target.test:443", pool, udp)
				done <- result{session, err}
			}()
			select {
			case <-wrapped.closing:
			case <-time.After(time.Second):
				t.Fatal("result read did not start the cancellation close")
			}
			select {
			case got := <-done:
				t.Fatalf("setup returned before cancellation closer exited: %v", got.err)
			case <-time.After(20 * time.Millisecond):
			}
			releaseClose()
			select {
			case got := <-done:
				if !errors.Is(got.err, context.Canceled) || got.session.Conn != nil || got.session.Reader != nil {
					t.Fatalf("canceled setup handed off a connection: error=%v session=%+v", got.err, got.session)
				}
				if got.session.PoolFallback || pool.Stats().Fallbacks != 0 {
					t.Fatal("canceled prepared setup attempted a fallback")
				}
			case <-time.After(time.Second):
				t.Fatal("setup did not exit after the closer completed")
			}
			select {
			case <-peerDone:
			case <-time.After(time.Second):
				t.Fatal("prepared peer did not exit")
			}
		})
	}
}

func TestTLSFreshCommandCancellationAndHandoff(t *testing.T) {
	for _, udp := range []bool{false, true} {
		for _, stage := range []string{"auth", "connect", "complete"} {
			t.Run(map[bool]string{false: "tcp/", true: "udp/"}[udp]+stage, func(t *testing.T) {
				certSource := httptest.NewTLSServer(nil)
				cert := certSource.TLS.Certificates[0]
				certSource.Close()
				listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				pin := sha256.Sum256(cert.Certificate[0])
				cfg := &config.ClientConfig{RemoteAddr: listener.Addr().String(), AuthToken: "cancel-handoff-test", CertificateFingerprint: hex.EncodeToString(pin[:])}
				ready := make(chan struct{})
				peers := make(chan net.Conn, 1)
				peerDone := make(chan error, 1)
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						peerDone <- err
						return
					}
					peers <- conn
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(3 * time.Second))
					r := bufio.NewReader(conn)
					for range 2 { // Both AUTH and CONNECT/UDP are pipelined.
						if _, err := tunnel.ReadLine(r); err != nil {
							peerDone <- err
							return
						}
					}
					if stage != "auth" {
						if err := tunnel.SendOK(conn); err != nil {
							peerDone <- err
							return
						}
					}
					close(ready)
					if stage != "complete" {
						_, _ = io.Copy(io.Discard, r)
						peerDone <- nil
						return
					}
					if _, err := io.WriteString(conn, "OK\nprefetched\n"); err != nil {
						peerDone <- err
						return
					}
					line, err := tunnel.ReadLine(r)
					if err == nil && line != "PING" {
						err = errors.New("unexpected post-setup payload")
					}
					if err == nil {
						_, err = io.WriteString(conn, "PONG\n")
					}
					peerDone <- err
				}()
				t.Cleanup(func() {
					cancel()
					listener.Close()
					select {
					case conn := <-peers:
						conn.(*tls.Conn).NetConn().Close()
					default:
					}
				})
				type result struct {
					session *remoteSession
					err     error
				}
				done := make(chan result, 1)
				go func() {
					session, err := openRemoteCommand(ctx, cfg, "target.test:443", nil, udp)
					done <- result{session, err}
				}()
				select {
				case <-ready:
				case <-time.After(2 * time.Second):
					t.Fatal("fresh setup did not reach the expected phase")
				}
				if stage != "complete" {
					cancel()
				}
				var got result
				select {
				case got = <-done:
				case <-time.After(time.Second):
					t.Fatal("fresh setup did not finish")
				}
				if stage != "complete" {
					if !errors.Is(got.err, context.Canceled) || got.session.Conn != nil || got.session.Reader != nil {
						t.Fatalf("cancellation lost its cause or handed off a connection: %v %+v", got.err, got.session)
					}
				} else {
					if got.err != nil {
						t.Fatal(got.err)
					}
					defer got.session.Conn.Close()
					cancel() // A successful handoff must detach setup cancellation.
					got.session.Conn.SetDeadline(time.Now().Add(time.Second))
					if line, err := tunnel.ReadLine(got.session.Reader); err != nil || line != "prefetched" {
						t.Fatalf("prefetched data changed: %q %v", line, err)
					}
					if _, err := io.WriteString(got.session.Conn, "PING\n"); err != nil {
						t.Fatal("completed setup retained cancellation ownership:", err)
					}
					if line, err := tunnel.ReadLine(got.session.Reader); err != nil || line != "PONG" {
						t.Fatalf("handed-off socket was closed: %q %v", line, err)
					}
				}
				select {
				case err := <-peerDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("fresh TLS peer did not exit")
				}
			})
		}
	}
}
