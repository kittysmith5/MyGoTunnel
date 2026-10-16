package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/preconnect"
	"mygotunnel/internal/tunnel"
)

const preparedACKPayload = "prefetched application payload\x00\n"

type preparedACKFixture struct {
	cfg      *config.ClientConfig
	pool     *preconnect.Pool
	accepted atomic.Int32
	ordinary atomic.Int32
}

// Both the pooled connection and a possible ordinary fallback use real local
// TLS connections. Factory refills are held until cancellation so connection
// counters distinguish a foreground retry from pool background activity.
func newPreparedACKFixture(t *testing.T, udp, ack bool, prepared func(net.Conn)) *preparedACKFixture {
	t.Helper()
	certSource := httptest.NewTLSServer(nil)
	certificate := certSource.TLS.Certificates[0]
	certSource.Close()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(certificate.Certificate[0])
	f := &preparedACKFixture{cfg: &config.ClientConfig{
		RemoteAddr: listener.Addr().String(), AuthToken: "prepared-ack-test-token",
		CertificateFingerprint: hex.EncodeToString(pin[:]),
	}}
	wantCommand := "CONNECT target.test:443"
	if udp {
		wantCommand = "UDP"
	}
	var peersMu sync.Mutex
	peers := make(map[net.Conn]struct{})
	var workers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			f.accepted.Add(1)
			peersMu.Lock()
			peers[raw] = struct{}{}
			peersMu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() {
					_ = raw.Close()
					peersMu.Lock()
					delete(peers, raw)
					peersMu.Unlock()
				}()
				conn := tls.Server(raw, &tls.Config{
					Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"},
				})
				_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
				reader := bufio.NewReader(conn)
				line, err := tunnel.ReadLine(reader)
				if err != nil || line != "AUTH "+f.cfg.AuthToken {
					t.Errorf("fixture AUTH: line=%q error=%v", line, err)
					return
				}
				line, err = tunnel.ReadLine(reader)
				if err != nil {
					t.Errorf("fixture command: %v", err)
					return
				}
				if line == "PREPARE" || line == "PREPARE ACK" {
					ready := "OK\nREADY\n"
					if ack {
						ready = "OK\nREADY ACK\n"
					}
					if _, err := io.WriteString(conn, ready); err != nil {
						t.Errorf("fixture READY: %v", err)
						return
					}
					line, err = tunnel.ReadLine(reader)
					if err != nil || line != wantCommand {
						t.Errorf("fixture prepared command: line=%q error=%v", line, err)
						return
					}
					prepared(conn)
					return
				}
				if line != wantCommand {
					t.Errorf("fixture ordinary command: %q", line)
					return
				}
				f.ordinary.Add(1)
				if _, err := io.WriteString(conn, "OK\nOK\n"+preparedACKPayload); err != nil {
					t.Errorf("fixture ordinary response: %v", err)
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-acceptDone
		peersMu.Lock()
		for peer := range peers {
			_ = peer.Close()
		}
		peersMu.Unlock()
		workers.Wait()
	})
	prepare := preconnect.NewPreparer(f.cfg)
	if !ack {
		prepare = func(ctx context.Context) (*preconnect.Entry, error) { return preconnect.Prepare(ctx, f.cfg) }
	}
	var calls atomic.Int32
	f.pool, err = preconnect.New(preconnect.Options{Size: 1}, func(ctx context.Context) (*preconnect.Entry, error) {
		if calls.Add(1) > 1 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		entry, err := prepare(ctx)
		if err == nil && entry.CommandACK != ack {
			t.Errorf("negotiated command ACK = %t, want %t", entry.CommandACK, ack)
		}
		return entry, err
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.pool.Close)
	deadline := time.Now().Add(3 * time.Second)
	for f.pool.IdleCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if f.pool.IdleCount() != 1 {
		t.Fatal("prepared ACK fixture pool did not become ready")
	}
	return f
}

func openPreparedACKTestCommand(ctx context.Context, f *preparedACKFixture, udp bool) (*remoteSession, error) {
	if udp {
		return openRemoteUDP(ctx, f.cfg, f.pool)
	}
	return openRemote(ctx, f.cfg, "target.test:443", f.pool)
}

func readPreparedACKPayload(t *testing.T, session *remoteSession) {
	t.Helper()
	defer closeUnusedRemote(session.Conn)
	if session.Reader.Buffered() < len(preparedACKPayload) {
		t.Fatalf("application payload was not preserved in control reader: buffered=%d", session.Reader.Buffered())
	}
	data := make([]byte, len(preparedACKPayload))
	if _, err := io.ReadFull(session.Reader, data); err != nil || string(data) != preparedACKPayload {
		t.Fatalf("prefetched payload=%q error=%v", data, err)
	}
}

func TestPreparedACKBlackholeFallsBackOnceWithinACKBudget(t *testing.T) {
	for _, udp := range []bool{false, true} {
		name := "CONNECT"
		if udp {
			name = "UDP"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newPreparedACKFixture(t, udp, true, func(conn net.Conn) { _, _ = io.Copy(io.Discard, conn) })
			ctx, cancel := context.WithTimeout(context.Background(), remoteSetupTimeout)
			defer cancel()
			started := time.Now()
			session, err := openPreparedACKTestCommand(ctx, f, udp)
			duration := time.Since(started)
			if err != nil {
				t.Fatal(err)
			}
			if !session.PoolFallback || session.PoolHit || duration < tunnel.PreparedAckTimeout-100*time.Millisecond || duration > tunnel.PreparedAckTimeout+2*time.Second {
				t.Fatalf("blackhole fallback: hit=%t fallback=%t duration=%v", session.PoolHit, session.PoolFallback, duration)
			}
			if session.AckDuration < tunnel.PreparedAckTimeout-100*time.Millisecond || session.AckDuration > duration {
				t.Fatalf("ACK timeout timing=%v, total=%v", session.AckDuration, duration)
			}
			if stats := f.pool.Stats(); stats.Hits != 1 || stats.Fallbacks != 1 || f.accepted.Load() != 2 || f.ordinary.Load() != 1 {
				t.Fatalf("fallback retried more than once: pool=%+v accepted=%d ordinary=%d", stats, f.accepted.Load(), f.ordinary.Load())
			}
			t.Logf("unresponsive prepared channel: total=%v ack_wait=%v ordinary_retries=%d", duration, session.AckDuration, f.ordinary.Load())
			readPreparedACKPayload(t, session)
		})
	}
}

func TestPreparedACKParentCancellationDoesNotFallback(t *testing.T) {
	for _, udp := range []bool{false, true} {
		name := "CONNECT"
		if udp {
			name = "UDP"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newPreparedACKFixture(t, udp, true, func(conn net.Conn) { _, _ = io.Copy(io.Discard, conn) })
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			started := time.Now()
			session, err := openPreparedACKTestCommand(ctx, f, udp)
			if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second || session.PoolFallback {
				t.Fatalf("parent cancellation: error=%v fallback=%t duration=%v", err, session.PoolFallback, time.Since(started))
			}
			if stats := f.pool.Stats(); stats.Fallbacks != 0 || f.accepted.Load() != 1 || f.ordinary.Load() != 0 {
				t.Fatalf("canceled parent triggered ordinary retry: pool=%+v accepted=%d ordinary=%d", stats, f.accepted.Load(), f.ordinary.Load())
			}
		})
	}
}

func TestPreparedACKExplicitParentCancelDoesNotFallback(t *testing.T) {
	for _, udp := range []bool{false, true} {
		name := "CONNECT"
		if udp {
			name = "UDP"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newPreparedACKFixture(t, udp, true, func(conn net.Conn) { _, _ = io.Copy(io.Discard, conn) })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cancelSoon := time.AfterFunc(50*time.Millisecond, cancel)
			defer cancelSoon.Stop()
			started := time.Now()
			session, err := openPreparedACKTestCommand(ctx, f, udp)
			if !errors.Is(err, context.Canceled) || time.Since(started) > time.Second || session.PoolFallback {
				t.Fatalf("explicit parent cancel: error=%v fallback=%t duration=%v", err, session.PoolFallback, time.Since(started))
			}
			if stats := f.pool.Stats(); stats.Fallbacks != 0 || f.accepted.Load() != 1 || f.ordinary.Load() != 0 {
				t.Fatalf("explicit cancel triggered ordinary retry: pool=%+v accepted=%d ordinary=%d", stats, f.accepted.Load(), f.ordinary.Load())
			}
		})
	}
}

func TestPreparedACKTargetWaitHasIndependentBudget(t *testing.T) {
	for _, udp := range []bool{false, true} {
		name := "CONNECT"
		if udp {
			name = "UDP"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			delay := tunnel.PreparedAckTimeout + 100*time.Millisecond
			f := newPreparedACKFixture(t, udp, true, func(conn net.Conn) {
				if _, err := io.WriteString(conn, "ACK\n"); err != nil {
					t.Errorf("fixture ACK: %v", err)
					return
				}
				time.Sleep(delay)
				if _, err := io.WriteString(conn, "OK\n"+preparedACKPayload); err != nil {
					t.Errorf("fixture delayed target response: %v", err)
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), remoteSetupTimeout)
			defer cancel()
			session, err := openPreparedACKTestCommand(ctx, f, udp)
			if err != nil || !session.PoolHit || session.PoolFallback {
				t.Fatalf("ACK followed by slow target failed: session=%+v error=%v", session, err)
			}
			if session.AckDuration <= 0 || session.AckDuration > tunnel.PreparedAckTimeout/2 || session.ControlDuration-session.AckDuration < delay-100*time.Millisecond {
				t.Fatalf("ACK timing includes target wait: ack=%v control=%v target_delay=%v", session.AckDuration, session.ControlDuration, delay)
			}
			if f.accepted.Load() != 1 || f.ordinary.Load() != 0 {
				t.Fatal("slow target triggered fallback after ACK")
			}
			readPreparedACKPayload(t, session)
		})
	}
}

func TestPreparedACKExplicitAndMalformedResponsesDoNotFallback(t *testing.T) {
	for _, udp := range []bool{false, true} {
		command := "CONNECT"
		if udp {
			command = "UDP"
		}
		for _, tc := range []struct {
			name, response, targetCode string
			wantErr                    error
		}{
			{name: "DNS before ACK", response: "ERR DNS\n", targetCode: "DNS"},
			{name: "LIMIT before ACK", response: "ERR LIMIT\n", targetCode: "LIMIT"},
			{name: "DNS after ACK", response: "ACK\nERR DNS\n", targetCode: "DNS"},
			{name: "unknown response", response: "UNKNOWN\n", wantErr: tunnel.ErrConnectResponse},
			{name: "unknown error code", response: "ERR FUTURE\n", wantErr: tunnel.ErrConnectResponse},
			{name: "unexpected OK", response: "OK\n", wantErr: tunnel.ErrConnectResponse},
			{name: "truncated ACK", response: "ACK", wantErr: io.ErrUnexpectedEOF},
			{name: "truncated error after ACK", response: "ACK\nERR DNS", wantErr: io.ErrUnexpectedEOF},
			{name: "overlong line", response: strings.Repeat("A", tunnel.MaxControlLineBytes) + "\n", wantErr: tunnel.ErrControlLineTooLong},
			{name: "control character", response: "A\x00CK\n"},
		} {
			t.Run(command+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				f := newPreparedACKFixture(t, udp, true, func(conn net.Conn) { _, _ = io.WriteString(conn, tc.response) })
				ctx, cancel := context.WithTimeout(context.Background(), remoteSetupTimeout)
				defer cancel()
				session, err := openPreparedACKTestCommand(ctx, f, udp)
				if err == nil || session.PoolFallback || !session.PoolHit {
					t.Fatalf("invalid ACK response retried: session=%+v error=%v", session, err)
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Fatalf("error=%v, want %v", err, tc.wantErr)
				}
				if tc.targetCode != "" {
					var target *tunnel.TargetError
					if !errors.As(err, &target) || target.Code != tc.targetCode {
						t.Fatalf("explicit ACK rejection lost typed error: %v", err)
					}
				}
				if stats := f.pool.Stats(); stats.Fallbacks != 0 || f.accepted.Load() != 1 || f.ordinary.Load() != 0 {
					t.Fatalf("protocol rejection opened a new connection: pool=%+v accepted=%d ordinary=%d", stats, f.accepted.Load(), f.ordinary.Load())
				}
			})
		}
	}
}

func TestPreparedACKAndLegacyOKPreservePrefetchedPayload(t *testing.T) {
	for _, udp := range []bool{false, true} {
		command := "CONNECT"
		if udp {
			command = "UDP"
		}
		for _, ack := range []bool{false, true} {
			mode := "legacy"
			if ack {
				mode = "ACK"
			}
			t.Run(command+"/"+mode, func(t *testing.T) {
				t.Parallel()
				f := newPreparedACKFixture(t, udp, ack, func(conn net.Conn) {
					response := "OK\n" + preparedACKPayload
					if ack {
						response = "ACK\n" + response
					}
					if _, err := io.WriteString(conn, response); err != nil {
						t.Errorf("fixture prepared success: %v", err)
					}
				})
				ctx, cancel := context.WithTimeout(context.Background(), remoteSetupTimeout)
				defer cancel()
				session, err := openPreparedACKTestCommand(ctx, f, udp)
				if err != nil || !session.PoolHit || session.PoolFallback || (!ack && session.AckDuration != 0) {
					t.Fatalf("prepared compatibility failed: session=%+v error=%v", session, err)
				}
				if f.accepted.Load() != 1 || f.ordinary.Load() != 0 {
					t.Fatal("successful pooled exchange opened ordinary connection")
				}
				readPreparedACKPayload(t, session)
			})
		}
	}
}
