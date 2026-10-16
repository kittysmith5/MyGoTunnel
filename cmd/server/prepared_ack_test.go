package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"mygotunnel/internal/admission"
	"mygotunnel/internal/config"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/tunnel"
)

type preparedACKTestServer struct {
	address   string
	counters  *admission.Counters
	idleSlots chan struct{}
}

func startPreparedACKTestServer(t *testing.T) *preparedACKTestServer {
	t.Helper()
	certServer := httptest.NewTLSServer(nil)
	cert := certServer.TLS.Certificates[0]
	certServer.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig(cert))
	if err != nil {
		t.Fatal(err)
	}
	s := &preparedACKTestServer{address: listener.Addr().String(), counters: &admission.Counters{}, idleSlots: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	resources := datagram.NewResources(4, 1<<20)
	finished := make(chan error, 1)
	go func() {
		finished <- admission.ServeContext(ctx, 0, listener, 1, 8, func(conn net.Conn, permit *admission.Permit) {
			handleTunnelContext(ctx, conn, &config.ServerConfig{AuthToken: "prepared-test-token"}, slog.New(slog.NewTextHandler(io.Discard, nil)), permit.Release,
				&serverPoolOptions{idleSlots: s.idleSlots, resumeSetup: permit.TryAcquire}, resources)
		}, nil, s.counters)
	}()
	t.Cleanup(func() {
		cancel()
		listener.Close()
		select {
		case err := <-finished:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("prepared TLS server did not stop")
		}
		if s.counters.Setup.Load() != 0 || s.counters.Open.Load() != 0 || len(s.idleSlots) != 0 {
			t.Error("prepared TLS server leaked admission capacity")
		}
		if stats := resources.Stats(); stats.Sockets != 0 || stats.BufferBytes != stats.CachedBytes {
			t.Errorf("prepared TLS server leaked UDP resources: %+v", stats)
		}
		resources.Close()
	})
	return s
}

func (s *preparedACKTestServer) prepare(t *testing.T, ack bool) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", s.address, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}) // generated local test certificate only
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.NetConn().Close() })
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)
	ready := "READY"
	if ack {
		err = tunnel.SendPrepareWithAck(conn, "prepared-test-token")
		ready = tunnel.PreparedAckReady
	} else {
		err = tunnel.SendPrepare(conn, "prepared-test-token")
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"OK", ready} {
		if line, err := tunnel.ReadLine(reader); err != nil || line != want {
			t.Fatalf("prepare reply = %q %v, want %q", line, err, want)
		}
	}
	s.waitCapacity(t, 1, 0, 1)
	return conn, reader
}

func (s *preparedACKTestServer) waitCapacity(t *testing.T, open, setup int64, idle int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if s.counters.Open.Load() == open && s.counters.Setup.Load() == setup && len(s.idleSlots) == idle {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("admission open/setup/idle = %d/%d/%d, want %d/%d/%d", s.counters.Open.Load(), s.counters.Setup.Load(), len(s.idleSlots), open, setup, idle)
}

func TestPreparedTLSCommandACKAndLegacyPayloadHandoff(t *testing.T) {
	for _, ack := range []bool{false, true} {
		for _, transport := range []string{"tcp", "udp"} {
			name := "legacy-" + transport
			if ack {
				name = "ack-" + transport
			}
			t.Run(name, func(t *testing.T) {
				s := startPreparedACKTestServer(t)
				conn, reader := s.prepare(t, ack)
				var frame []byte
				var command bytes.Buffer
				targetDone := make(chan error, 1)
				if transport == "tcp" {
					target, err := net.Listen("tcp4", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { target.Close() })
					go func() {
						peer, err := target.Accept()
						if err != nil {
							targetDone <- err
							return
						}
						defer peer.Close()
						peer.SetDeadline(time.Now().Add(3 * time.Second))
						_, err = io.Copy(peer, peer)
						if err == nil {
							_, err = io.WriteString(peer, "after-eof")
						}
						targetDone <- err
					}()
					command.WriteString("CONNECT " + target.Addr().String() + "\n")
					frame = []byte("prefetched\x00\n\xffpayload")
					command.Write(frame)
				} else {
					_, frame = udpIsolationEcho(t)
					command.WriteString("UDP\n")
					if err := tunnel.WriteDatagram(&command, frame); err != nil {
						t.Fatal(err)
					}
				}
				// The command and first binary payload share one TLS write, forcing
				// the control reader to preserve prefetched bytes for relay.
				if _, err := conn.Write(command.Bytes()); err != nil {
					t.Fatal(err)
				}
				if ack {
					if line, err := tunnel.ReadLine(reader); err != nil || line != tunnel.CommandAcknowledged {
						t.Fatalf("command ACK = %q %v", line, err)
					}
				}
				if line, err := tunnel.ReadLine(reader); err != nil || line != "OK" {
					t.Fatalf("target reply = %q %v; legacy clients must not receive ACK", line, err)
				}
				s.waitCapacity(t, 1, 0, 0)
				if transport == "tcp" {
					got := make([]byte, len(frame))
					if _, err := io.ReadFull(reader, got); err != nil || !bytes.Equal(got, frame) {
						t.Fatalf("buffered TCP payload = %q %v", got, err)
					}
					if err := conn.CloseWrite(); err != nil {
						t.Fatal(err)
					}
					if got, err := io.ReadAll(reader); err != nil || string(got) != "after-eof" {
						t.Fatalf("TCP half-close response = %q %v", got, err)
					}
					if err := <-targetDone; err != nil {
						t.Fatal(err)
					}
				} else if got, err := tunnel.ReadDatagram(reader); err != nil || !bytes.Equal(got, frame) {
					t.Fatalf("buffered UDP frame = %v %v", got, err)
				}
				conn.NetConn().Close()
				s.waitCapacity(t, 0, 0, 0)
			})
		}
	}
}

func TestPreparedACKSetupRejectionReturnsLimitWithoutACK(t *testing.T) {
	s := startPreparedACKTestServer(t)
	conn, reader := s.prepare(t, true)
	// A second accepted connection stalls before TLS authentication, holding
	// the sole setup permit while the prepared connection requests UDP.
	blocker, err := net.DialTimeout("tcp", s.address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { blocker.Close() })
	s.waitCapacity(t, 2, 1, 1)
	started := time.Now()
	if err := tunnel.SendUDPAssociate(conn); err != nil {
		t.Fatal(err)
	}
	if line, err := tunnel.ReadLine(reader); err != nil || line != "ERR LIMIT" {
		t.Fatalf("setup rejection = %q %v, want ERR LIMIT before any ACK", line, err)
	}
	if line, err := tunnel.ReadLine(reader); err != io.EOF || line != "" {
		t.Fatalf("setup rejection did not close: %q %v", line, err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("setup rejection exceeded bounded reply budget: %v", elapsed)
	}
	s.waitCapacity(t, 1, 1, 0)
	blocker.Close()
	s.waitCapacity(t, 0, 0, 0)
}
