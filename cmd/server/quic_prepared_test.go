package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"mygotunnel/internal/admission"
	"mygotunnel/internal/authlimit"
	"mygotunnel/internal/config"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/quicudp"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
)

func newQUICPreparedTestServer(t *testing.T, maxSetup, maxIdle int, accepted ...chan *quicudp.Conn) (*quicTestServer, chan struct{}) {
	t.Helper()
	certSource := httptest.NewTLSServer(nil)
	cert := certSource.TLS.Certificates[0]
	certSource.Close()
	resources := datagram.NewResources(32, 8<<20)
	t.Cleanup(func() {
		resources.Close()
		if stats := resources.Stats(); stats.Sockets != 0 || stats.BufferBytes != 0 {
			t.Errorf("prepared QUIC server leaked resources: %+v", stats)
		}
	})
	udp, err := quicudp.Listen("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{quicudp.ALPN}}, resources, time.Second, 8)
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := tls.Listen("tcp", "127.0.0.1:0", serverTLSConfig(cert))
	if err != nil {
		udp.Close()
		t.Fatal(err)
	}
	listener, err := admission.MergeListeners(tcp, udp)
	if err != nil {
		tcp.Close()
		udp.Close()
		t.Fatal(err)
	}
	pin := sha256.Sum256(cert.Certificate[0])
	idle := make(chan struct{}, maxIdle)
	ctx, cancel := context.WithCancel(context.Background())
	s := &quicTestServer{cfg: &config.ServerConfig{AuthToken: "prepared-quic-test-token"},
		client:    &config.ClientConfig{AuthToken: "prepared-quic-test-token", CertificateFingerprint: hex.EncodeToString(pin[:])},
		resources: resources, counters: &admission.Counters{}, limiter: authlimit.New(64, 5, time.Minute, time.Minute),
		tcpAddr: tcp.Addr().String(), addr: udp.Addr().String(), cancel: cancel, done: make(chan struct{})}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() {
		defer close(s.done)
		s.err = admission.ServeContext(ctx, 0, listener, maxSetup, 8, func(conn net.Conn, permit *admission.Permit) {
			options := &serverPoolOptions{idleSlots: idle, resumeSetup: permit.TryAcquire, abortContext: permit.AbortContext()}
			if _, ok := conn.(*quicudp.Conn); ok {
				if len(accepted) != 0 {
					accepted[0] <- conn.(*quicudp.Conn)
				}
				handleQUICUDPTunnelWithPool(conn, s.cfg, logger, permit, options, s.limiter, resources)
				return
			}
			handleTunnelContextWithLimiter(ctx, conn, s.cfg, logger, permit.Release, options, s.limiter, resources)
		}, nil, s.counters)
	}()
	t.Cleanup(func() {
		s.stop(t)
		if len(idle) != 0 {
			t.Error("prepared QUIC server retained idle slots after shutdown")
		}
	})
	return s, idle
}

func prepareQUICForTest(t *testing.T, s *quicTestServer, c *quicudp.Conn, ack bool) *bufio.Reader {
	t.Helper()
	var err error
	ready := "READY"
	if ack {
		err = tunnel.SendPrepareWithAck(c, s.client.AuthToken)
		ready = tunnel.PreparedAckReady
	} else {
		err = tunnel.SendPrepare(c, s.client.AuthToken)
	}
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(c)
	for _, want := range []string{"OK", ready} {
		if got, err := tunnel.ReadLine(reader); err != nil || got != want {
			t.Fatalf("prepared QUIC response %q, %v; want %q", got, err, want)
		}
	}
	return reader
}

func activatePreparedQUICForTest(t *testing.T, c *quicudp.Conn, reader *bufio.Reader, ack bool) {
	t.Helper()
	if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SendUDPAssociate(c); err != nil {
		t.Fatal(err)
	}
	wants := []string{"OK"}
	if ack {
		wants = []string{tunnel.CommandAcknowledged, "OK"}
	}
	for _, want := range wants {
		if got, err := tunnel.ReadLine(reader); err != nil || got != want {
			t.Fatalf("prepared UDP response %q, %v; want %q", got, err, want)
		}
	}
	if reader.Buffered() != 0 {
		t.Fatal("unexpected prepared QUIC control payload")
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	c.EnableDatagrams()
}

func TestQUICPreparedLegacyAndACKDatagramHandoff(t *testing.T) {
	for _, ack := range []bool{false, true} {
		name := "legacy"
		if ack {
			name = "ack"
		}
		t.Run(name, func(t *testing.T) {
			s, idle := newQUICPreparedTestServer(t, 1, 1)
			c := dialQUICTest(t, s, quicClientResources(t), s.client.CertificateFingerprint)
			reader := prepareQUICForTest(t, s, c, ack)
			quicWait(t, "prepared setup release", func() bool { return len(idle) == 1 && s.counters.Setup.Load() == 0 })
			if err := c.WritePacket([]byte("premature")); err != quicudp.ErrNotAuthorized {
				t.Fatalf("prepared client accepted business datagram: %v", err)
			}
			activatePreparedQUICForTest(t, c, reader, ack)
			for _, size := range []int{60000, 0, 64, 1400} {
				checkQUICEcho(t, c, quicEchoTarget(t), size)
			}
			quicWait(t, "active UDP released idle/setup", func() bool { return len(idle) == 0 && s.counters.Setup.Load() == 0 })
			c.Close()
			quicWait(t, "prepared connection cleanup", func() bool { return s.counters.Open.Load() == 0 })
		})
	}
}

func TestQUICPreparedSurvivesAuthenticationDeadline(t *testing.T) {
	s, idle := newQUICPreparedTestServer(t, 1, 1)
	c := dialQUICTest(t, s, quicClientResources(t), s.client.CertificateFingerprint)
	reader := prepareQUICForTest(t, s, c, true)
	if err := c.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	// Both stream creation and AUTH normally expire after five seconds. READY
	// must instead install the authenticated prepared timeout, without setup use.
	time.Sleep(5100 * time.Millisecond)
	if len(idle) != 1 || s.counters.Setup.Load() != 0 {
		t.Fatal("prepared channel expired at authentication deadline or retained setup")
	}
	activatePreparedQUICForTest(t, c, reader, true)
	checkQUICEcho(t, c, quicEchoTarget(t), 64)
}

func TestQUICPreparedIdleBudgetSharedWithTCP(t *testing.T) {
	s, idle := newQUICPreparedTestServer(t, 2, 1)
	tlsConfig, err := quicudp.ClientTLSConfig(s.tcpAddr, "localhost", s.client.CertificateFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig.NextProtos = []string{"http/1.1"}
	tcp, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", s.tcpAddr, tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcp.NetConn().Close() })
	tcp.SetDeadline(time.Now().Add(3 * time.Second))
	if err := tunnel.SendPrepareWithAck(tcp, s.client.AuthToken); err != nil {
		t.Fatal(err)
	}
	tcpReader := bufio.NewReader(tcp)
	for _, want := range []string{"OK", tunnel.PreparedAckReady} {
		if got, err := tunnel.ReadLine(tcpReader); err != nil || got != want {
			t.Fatalf("TCP prepare response %q %v", got, err)
		}
	}
	quicWait(t, "TCP idle occupying shared slot", func() bool { return len(idle) == 1 && s.counters.Setup.Load() == 0 })
	c := dialQUICTest(t, s, quicClientResources(t), s.client.CertificateFingerprint)
	if err := tunnel.SendPrepareWithAck(c, s.client.AuthToken); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(c)
	assertQUICPreparedLimit(t, reader, "BUSY")
	quicWait(t, "rejected QUIC setup release", func() bool { return s.counters.Open.Load() == 1 && s.counters.Setup.Load() == 0 })
	tcp.NetConn().Close()
	quicWait(t, "TCP shared idle release", func() bool { return len(idle) == 0 && s.counters.Open.Load() == 0 })
	warm := dialQUICTest(t, s, quicClientResources(t), s.client.CertificateFingerprint)
	prepareQUICForTest(t, s, warm, true)
	quicWait(t, "QUIC reused released shared idle", func() bool { return len(idle) == 1 && s.counters.Setup.Load() == 0 })
	warm.Close()
	quicWait(t, "closed QUIC idle release", func() bool { return len(idle) == 0 && s.counters.Open.Load() == 0 })
}

func TestQUICPreparedZeroIdleReturnsBusy(t *testing.T) {
	s, idle := newQUICPreparedTestServer(t, 1, 0)
	c := dialQUICTest(t, s, quicClientResources(t), s.client.CertificateFingerprint)
	if err := tunnel.SendPrepareWithAck(c, s.client.AuthToken); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(c)
	assertQUICPreparedLimit(t, reader, "BUSY")
	quicWait(t, "disabled idle cleanup", func() bool { return len(idle) == 0 && s.counters.Open.Load() == 0 && s.counters.Setup.Load() == 0 })
	// Ordinary UDP remains available when authenticated preconnections are off.
	ordinary := dialQUICTest(t, s, quicClientResources(t), s.client.CertificateFingerprint)
	authorizeQUICTest(t, ordinary, s.client.AuthToken)
	checkQUICEcho(t, ordinary, quicEchoTarget(t), 64)
}

func TestQUICPreparedReacquiresSharedSetup(t *testing.T) {
	s, idle := newQUICPreparedTestServer(t, 1, 1)
	c := dialQUICTest(t, s, quicClientResources(t), s.client.CertificateFingerprint)
	reader := prepareQUICForTest(t, s, c, true)
	quicWait(t, "prepared setup released", func() bool { return s.counters.Setup.Load() == 0 })
	blocker, err := net.DialTimeout("tcp", s.tcpAddr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	quicWait(t, "TCP took shared setup", func() bool { return s.counters.Setup.Load() == 1 })
	if err := tunnel.SendUDPAssociate(c); err != nil {
		t.Fatal(err)
	}
	assertQUICPreparedLimit(t, reader, "ERR LIMIT")
	quicWait(t, "failed setup reacquisition cleanup", func() bool { return len(idle) == 0 && s.counters.Open.Load() == 1 && s.counters.Setup.Load() == 1 })
	if stats := s.resources.Stats(); stats.Sockets != 1 || stats.BufferBytes != 0 {
		t.Fatalf("rejected prepared command allocated UDP targets: %+v", stats)
	}
}

func TestQUICPreparedRejectsInvalidCommandAndPayload(t *testing.T) {
	for _, command := range []string{"CONNECT 127.0.0.1:1\n", "UDP\nforbidden-data"} {
		t.Run(command[:3], func(t *testing.T) {
			s, idle := newQUICPreparedTestServer(t, 1, 1)
			c := dialQUICTest(t, s, quicClientResources(t), s.client.CertificateFingerprint)
			reader := prepareQUICForTest(t, s, c, true)
			if _, err := io.WriteString(c, command); err != nil {
				t.Fatal(err)
			}
			if got, err := tunnel.ReadLine(reader); err == nil && (got == "OK" || got == tunnel.CommandAcknowledged) {
				t.Fatalf("invalid QUIC command accepted: %q", got)
			}
			quicWait(t, "invalid prepared command cleanup", func() bool { return len(idle) == 0 && s.counters.Open.Load() == 0 && s.counters.Setup.Load() == 0 })
			if stats := s.resources.Stats(); stats.Sockets != 1 || stats.BufferBytes != 0 {
				t.Fatalf("invalid prepared command allocated targets: %+v", stats)
			}
		})
	}
}

func TestQUICPreparedAuthenticationFailureDoesNotReserveIdle(t *testing.T) {
	s, idle := newQUICPreparedTestServer(t, 1, 1)
	c := dialQUICTest(t, s, quicClientResources(t), s.client.CertificateFingerprint)
	if err := tunnel.SendPrepareWithAck(c, "wrong-token"); err != nil {
		t.Fatal(err)
	}
	if got, err := tunnel.ReadLine(bufio.NewReader(c)); err == nil && got == "OK" {
		t.Fatal("wrong token was authenticated for prepared QUIC")
	}
	quicWait(t, "failed authentication cleanup", func() bool { return len(idle) == 0 && s.counters.Open.Load() == 0 && s.counters.Setup.Load() == 0 })
}

func TestQUICPreparedDoesNotRelayEarlyDatagrams(t *testing.T) {
	accepted := make(chan *quicudp.Conn, 1)
	s, idle := newQUICPreparedTestServer(t, 1, 1, accepted)
	target := quicEchoTarget(t)
	tlsConfig, err := quicudp.ClientTLSConfig(s.addr, "localhost", s.client.CertificateFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	q, err := quic.DialAddr(ctx, s.addr, tlsConfig, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer q.CloseWithError(0, "test finished")
	control, err := q.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	control.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(control, "AUTH "+s.client.AuthToken+"\nPREPARE ACK\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(control)
	for _, want := range []string{"OK", tunnel.PreparedAckReady} {
		if got, err := tunnel.ReadLine(reader); err != nil || got != want {
			t.Fatalf("raw prepared response %q %v", got, err)
		}
	}
	packet := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "127.0.0.1", Port: uint16(target.LocalAddr().(*net.UDPAddr).Port)}, []byte("discard before UDP activation"))
	fragments, err := quicudp.Fragments(packet, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range fragments {
		if err := q.SendDatagram(fragment); err != nil {
			t.Fatal(err)
		}
	}
	// A complete DATAGRAM may be received but must not allocate target or
	// reassembly state while this authenticated connection is merely idle.
	var serverConn *quicudp.Conn
	select {
	case serverConn = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("server did not accept prepared QUIC connection")
	}
	quicWait(t, "discarded pre-activation datagram", func() bool { return serverConn.PreAuthDrops() > 0 })
	if stats := s.resources.Stats(); len(idle) != 1 || stats.Sockets != 1 || stats.BufferBytes != 0 {
		t.Fatalf("prepared datagram allocated target resources: idle=%d stats=%+v", len(idle), stats)
	}
	if _, err := io.WriteString(control, "UDP\n"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{tunnel.CommandAcknowledged, "OK"} {
		if got, err := tunnel.ReadLine(reader); err != nil || got != want {
			t.Fatalf("raw activation response %q %v", got, err)
		}
	}
	receiveCtx, receiveCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer receiveCancel()
	if _, err := q.ReceiveDatagram(receiveCtx); err == nil {
		t.Fatal("prepared datagram was retained and replayed after UDP activation")
	}
}

func assertQUICPreparedLimit(t *testing.T, reader *bufio.Reader, expected string) {
	t.Helper()
	for {
		got, err := tunnel.ReadLine(reader)
		if errors.Is(err, quicudp.ErrLimit) {
			return // Explicit QUIC close reason survives undelivered stream bytes.
		}
		if err != nil {
			t.Fatalf("prepared limit lost explicit failure: %v", err)
		}
		if got == expected {
			return
		}
		if got != "OK" {
			t.Fatalf("unexpected prepared limit response: %q", got)
		}
	}
}
