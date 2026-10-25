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
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/preconnect"
	"mygotunnel/internal/quicudp"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
)

type quicPoolFixture struct {
	cfg             *config.ClientConfig
	pool            *preconnect.Pool
	resources       *datagram.Resources
	accepted        atomic.Int32
	authenticated   atomic.Int32
	ordinary        atomic.Int32
	factoryCalls    atomic.Int32
	preparedCommand chan struct{}
}

type quicPoolFixtureOptions struct {
	maxSockets int
	poolSize   int
	refill     bool
}

// Only the first factory call opens a connection. Later refill calls wait for
// cancellation, so a second accepted connection can only be a foreground
// fallback. The listener, TLS handshake, control stream and DATAGRAMs are real.
func newQUICPoolFixture(t *testing.T, mode string, options ...quicPoolFixtureOptions) *quicPoolFixture {
	t.Helper()
	opts := quicPoolFixtureOptions{maxSockets: 8, poolSize: 1}
	if len(options) > 0 {
		opts = options[0]
	}
	certSource := httptest.NewTLSServer(nil)
	certificate := certSource.TLS.Certificates[0]
	certSource.Close()
	serverResources := datagram.NewResources(8, 8<<20)
	listener, err := quicudp.Listen("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate}, NextProtos: []string{quicudp.ALPN},
	}, serverResources, time.Second, 8)
	if err != nil {
		serverResources.Close()
		t.Fatal(err)
	}
	pin := sha256.Sum256(certificate.Certificate[0])
	f := &quicPoolFixture{
		cfg: &config.ClientConfig{
			RemoteAddr: listener.Addr().String(), AuthToken: "quic-pool-fixture",
			CertificateFingerprint: hex.EncodeToString(pin[:]), UDPTransport: "quic",
		},
		resources: datagram.NewResources(opts.maxSockets, 8<<20), preparedCommand: make(chan struct{}),
	}
	var peersMu sync.Mutex
	peers := make(map[net.Conn]struct{})
	var workers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			f.accepted.Add(1)
			peersMu.Lock()
			peers[conn] = struct{}{}
			peersMu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() {
					_ = conn.Close()
					peersMu.Lock()
					delete(peers, conn)
					peersMu.Unlock()
				}()
				_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
				reader := bufio.NewReader(conn)
				line, err := tunnel.ReadLine(reader)
				if err != nil || line != "AUTH "+f.cfg.AuthToken {
					t.Errorf("QUIC fixture AUTH failed: %v", err)
					return
				}
				f.authenticated.Add(1)
				line, err = tunnel.ReadLine(reader)
				if err != nil {
					t.Errorf("QUIC fixture command failed: %v", err)
					return
				}
				if line == "PREPARE ACK" {
					if _, err := io.WriteString(conn, "OK\nREADY ACK\n"); err != nil {
						t.Errorf("QUIC fixture READY failed: %v", err)
						return
					}
					line, err = tunnel.ReadLine(reader)
					if err != nil {
						// A pool may retire an unused prepared connection during
						// cleanup or renewal without ever sending a UDP command.
						return
					}
					if line != "UDP" {
						t.Errorf("QUIC fixture prepared UDP failed: %v", err)
						return
					}
					close(f.preparedCommand)
					switch mode {
					case "eof":
						return
					case "silent":
						_, _ = io.Copy(io.Discard, conn)
						return
					case "limit-before-ack", "limit-after-ack", "invalid-ack":
						response := "ERR LIMIT\n"
						if mode == "limit-after-ack" {
							response = "ACK\n" + response
						} else if mode == "invalid-ack" {
							response = "OK\n"
						}
						if _, err := io.WriteString(conn, response); err != nil {
							t.Errorf("QUIC fixture rejection failed: %v", err)
						}
						_, _ = io.Copy(io.Discard, conn)
						return
					case "echo":
					default:
						t.Errorf("unknown QUIC fixture mode")
						return
					}
					tunnel.EnableDatagrams(conn)
					if _, err := io.WriteString(conn, "ACK\nOK\n"); err != nil {
						t.Errorf("QUIC fixture prepared success failed: %v", err)
						return
					}
				} else if line == "UDP" {
					f.ordinary.Add(1)
					tunnel.EnableDatagrams(conn)
					if _, err := io.WriteString(conn, "OK\nOK\n"); err != nil {
						t.Errorf("QUIC fixture ordinary success failed: %v", err)
						return
					}
				} else {
					t.Errorf("unexpected QUIC fixture command")
					return
				}
				_ = conn.SetDeadline(time.Time{})
				packets := conn.(*quicudp.Conn)
				for {
					packet, err := packets.ReadPacket()
					if err != nil {
						return
					}
					err = packets.WritePacket(packet.Data)
					packet.Release()
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		if f.pool != nil {
			f.pool.Close()
		}
		_ = listener.Close()
		<-acceptDone
		peersMu.Lock()
		for peer := range peers {
			_ = peer.Close()
		}
		peersMu.Unlock()
		workers.Wait()
		if stats := f.resources.Stats(); stats.Sockets != 0 || stats.BufferBytes != stats.CachedBytes {
			t.Errorf("QUIC pool client resources retained: %+v", stats)
		}
		f.resources.Close()
		serverResources.Close()
	})
	prepare := preconnect.NewQUICPreparer(f.cfg, f.resources)
	f.pool, err = preconnect.New(preconnect.Options{Size: opts.poolSize}, func(ctx context.Context) (*preconnect.Entry, error) {
		if f.factoryCalls.Add(1) > 1 && !opts.refill {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return prepare(ctx)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for f.pool.IdleCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if f.pool.IdleCount() != 1 {
		t.Fatal("QUIC fixture pool did not become ready")
	}
	return f
}

func echoQUICPoolPayloads(t *testing.T, session *remoteSession) {
	t.Helper()
	conn, ok := session.Conn.(*quicudp.Conn)
	if !ok {
		t.Fatal("session is not a QUIC connection")
	}
	for _, size := range []int{0, 64, 1400, 60000} {
		want := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "echo.invalid", Port: 53}, bytes.Repeat([]byte{byte(size + 1)}, size))
		if err := conn.WritePacket(want); err != nil {
			t.Fatalf("QUIC payload %d write: %v", size, err)
		}
		received := make(chan datagram.Packet, 1)
		failure := make(chan error, 1)
		go func() {
			packet, err := conn.ReadPacket()
			if err != nil {
				failure <- err
				return
			}
			received <- packet
		}()
		select {
		case packet := <-received:
			matches := bytes.Equal(packet.Data, want)
			packet.Release()
			if !matches {
				t.Fatalf("QUIC payload %d changed", size)
			}
		case err := <-failure:
			t.Fatalf("QUIC payload %d read: %v", size, err)
		case <-time.After(2 * time.Second):
			_ = conn.Close()
			select {
			case packet := <-received:
				packet.Release()
			case <-failure:
			case <-time.After(time.Second):
				t.Error("QUIC packet reader did not stop on close")
			}
			t.Fatalf("QUIC payload %d echo timed out", size)
		}
	}
}

func TestQUICPoolHitHandsOffIndependentDatagramSession(t *testing.T) {
	f := newQUICPoolFixture(t, "echo")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	session, err := openRemoteQUICUDP(ctx, f.cfg, f.resources, f.pool)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Conn.Close()
	if !session.PoolHit || session.PoolFallback || session.QUICDuration != 0 || session.AckDuration <= 0 || session.ControlDuration < session.AckDuration {
		t.Fatalf("QUIC pool timing/ownership: hit=%t fallback=%t handshake=%v ack=%v control=%v", session.PoolHit, session.PoolFallback, session.QUICDuration, session.AckDuration, session.ControlDuration)
	}
	if stats := f.pool.Stats(); stats.Hits != 1 || stats.Fallbacks != 0 || f.accepted.Load() != 1 || f.authenticated.Load() != 1 || f.ordinary.Load() != 0 {
		t.Fatalf("QUIC pool acquisition: stats=%+v accepted=%d authenticated=%d ordinary=%d", stats, f.accepted.Load(), f.authenticated.Load(), f.ordinary.Load())
	}
	// Neither shutting down the pool nor canceling the completed setup owns this
	// connection after handoff. Business DATAGRAMs must continue normally.
	f.pool.Close()
	cancel()
	echoQUICPoolPayloads(t, session)
}

func TestQUICPoolTransportFailureFallsBackOnceAndAuthenticatesAgain(t *testing.T) {
	for _, mode := range []string{"eof", "silent"} {
		t.Run(mode, func(t *testing.T) {
			f := newQUICPoolFixture(t, mode)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			started := time.Now()
			session, err := openRemoteQUICUDP(ctx, f.cfg, f.resources, f.pool)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Conn.Close()
			if !session.PoolFallback || session.PoolHit || session.QUICDuration <= 0 {
				t.Fatalf("QUIC fallback state: hit=%t fallback=%t handshake=%v", session.PoolHit, session.PoolFallback, session.QUICDuration)
			}
			if stats := f.pool.Stats(); stats.Hits != 1 || stats.Fallbacks != 1 || f.accepted.Load() != 2 || f.authenticated.Load() != 2 || f.ordinary.Load() != 1 {
				t.Fatalf("QUIC fallback count/auth: stats=%+v accepted=%d authenticated=%d ordinary=%d", stats, f.accepted.Load(), f.authenticated.Load(), f.ordinary.Load())
			}
			if mode == "silent" && (session.AckDuration < tunnel.PreparedAckTimeout-100*time.Millisecond || session.ControlDuration < session.AckDuration || time.Since(started) > tunnel.PreparedAckTimeout+2*time.Second) {
				t.Fatalf("QUIC silent ACK budget: ack=%v control=%v elapsed=%v", session.AckDuration, session.ControlDuration, time.Since(started))
			}
			echoQUICPoolPayloads(t, session)
		})
	}
}

func TestQUICPoolExplicitRejectionDoesNotFallback(t *testing.T) {
	for _, mode := range []string{"limit-before-ack", "limit-after-ack", "invalid-ack"} {
		t.Run(mode, func(t *testing.T) {
			f := newQUICPoolFixture(t, mode)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			session, err := openRemoteQUICUDP(ctx, f.cfg, f.resources, f.pool)
			if session.Conn != nil || session.PoolFallback || !session.PoolHit {
				t.Fatalf("QUIC rejection retried or handed off connection: hit=%t fallback=%t conn=%v", session.PoolHit, session.PoolFallback, session.Conn != nil)
			}
			var target *tunnel.TargetError
			if mode == "invalid-ack" {
				if !errors.Is(err, tunnel.ErrConnectResponse) {
					t.Fatalf("QUIC invalid ACK classification: %v", err)
				}
			} else if !errors.As(err, &target) || target.Code != "LIMIT" {
				t.Fatalf("QUIC rejection lost explicit code: %v", err)
			}
			if stats := f.pool.Stats(); stats.Fallbacks != 0 || f.accepted.Load() != 1 || f.ordinary.Load() != 0 {
				t.Fatalf("QUIC rejection opened fallback: stats=%+v accepted=%d ordinary=%d", stats, f.accepted.Load(), f.ordinary.Load())
			}
		})
	}
}

func TestQUICPoolParentCancellationDoesNotFallback(t *testing.T) {
	f := newQUICPoolFixture(t, "silent")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		session *remoteSession
		err     error
	}
	done := make(chan result, 1)
	go func() {
		session, err := openRemoteQUICUDP(ctx, f.cfg, f.resources, f.pool)
		done <- result{session, err}
	}()
	select {
	case <-f.preparedCommand:
	case <-time.After(time.Second):
		t.Fatal("QUIC prepared command did not arrive")
	}
	cancel()
	select {
	case got := <-done:
		if !errors.Is(got.err, context.Canceled) || got.session.PoolFallback || got.session.Conn != nil {
			t.Fatalf("QUIC cancellation: err=%v fallback=%t conn=%v", got.err, got.session.PoolFallback, got.session.Conn != nil)
		}
	case <-time.After(time.Second):
		t.Fatal("QUIC parent cancellation did not interrupt ACK wait")
	}
	if stats := f.pool.Stats(); stats.Fallbacks != 0 || f.accepted.Load() != 1 || f.ordinary.Load() != 0 {
		t.Fatalf("QUIC cancellation opened fallback: stats=%+v accepted=%d ordinary=%d", stats, f.accepted.Load(), f.ordinary.Load())
	}
}

func TestQUICPoolLeavesSocketForForegroundRelay(t *testing.T) {
	f := newQUICPoolFixture(t, "echo", quicPoolFixtureOptions{maxSockets: 2, poolSize: 2, refill: true})
	// Wait for both initial fill workers. The preparer must reserve a slot for
	// the local UDP relay atomically, even when several workers run together.
	deadline := time.Now().Add(time.Second)
	for f.factoryCalls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if f.factoryCalls.Load() < 2 {
		t.Fatal("low-budget test did not exercise concurrent pool fills")
	}
	if stats := f.resources.Stats(); stats.Sockets != 1 || f.pool.IdleCount() != 1 {
		t.Fatalf("QUIC pool consumed foreground socket reserve: resources=%+v idle=%d", stats, f.pool.IdleCount())
	}
	if !f.resources.AcquireSocket() {
		t.Fatal("QUIC pool starved the foreground UDP relay")
	}
	defer f.resources.ReleaseSocket()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	session, err := openRemoteQUICUDP(ctx, f.cfg, f.resources, f.pool)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Conn.Close()
	if !session.PoolHit || session.PoolFallback || session.QUICDuration != 0 {
		t.Fatalf("low-budget association did not use prepared QUIC: hit=%t fallback=%t handshake=%v", session.PoolHit, session.PoolFallback, session.QUICDuration)
	}
	if stats := f.resources.Stats(); stats.Sockets != 2 || f.accepted.Load() != 1 {
		t.Fatalf("low-budget foreground bypassed socket cap: resources=%+v accepted=%d", stats, f.accepted.Load())
	}
	f.pool.Close()
	echoQUICPoolPayloads(t, session)
	if err := session.Conn.Close(); err != nil {
		t.Fatal(err)
	}
	if stats := f.resources.Stats(); stats.Sockets != 1 || stats.BufferBytes != stats.CachedBytes {
		t.Fatalf("low-budget association retained QUIC resources: %+v", stats)
	}
}
