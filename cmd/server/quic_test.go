package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
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

type quicTestServer struct {
	path      string
	cfg       *config.ServerConfig
	client    *config.ClientConfig
	certs     *certificateManager
	resources *datagram.Resources
	counters  *admission.Counters
	limiter   *authlimit.Limiter
	tcpAddr   string
	addr      string
	cancel    context.CancelFunc
	done      chan struct{}
	err       error
}

func newQUICTestServer(t *testing.T, grace time.Duration, maxSetup int, mutate func(*config.ServerConfig)) *quicTestServer {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.json")
	code, err := config.InitializeServer(path, "localhost:9001", ":9001")
	if err != nil {
		t.Fatal(err)
	}
	clientCfg, err := config.DecodeConnection(code)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadServerConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(cfg)
		writeReloadConfig(t, path, cfg)
	}
	certs, err := newCertificateManager(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	resources := datagram.NewResources(32, 8<<20)
	t.Cleanup(func() {
		resources.Close()
		if s := resources.Stats(); s.BufferBytes != 0 || s.Sockets != 0 {
			t.Errorf("QUIC server leaked process resources: %+v", s)
		}
	})
	udp, err := quicudp.Listen("127.0.0.1:0", certs.quicTLSConfig(), resources, 250*time.Millisecond, 8)
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := tls.Listen("tcp", "127.0.0.1:0", certs.tlsConfig())
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
	ctx, cancel := context.WithCancel(context.Background())
	s := &quicTestServer{path: path, cfg: cfg, client: clientCfg, certs: certs, resources: resources,
		counters: &admission.Counters{}, limiter: authlimit.New(64, 5, time.Minute, time.Minute),
		tcpAddr: tcp.Addr().String(), addr: udp.Addr().String(), cancel: cancel, done: make(chan struct{})}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() {
		defer close(s.done)
		s.err = admission.ServeContext(ctx, grace, listener, maxSetup, 8, func(c net.Conn, p *admission.Permit) {
			if _, ok := c.(*quicudp.Conn); ok {
				handleQUICUDPTunnel(c, cfg, logger, p, s.limiter, resources)
				return
			}
			handleTunnelContextWithLimiter(ctx, c, cfg, logger, p.Release, &serverPoolOptions{abortContext: p.AbortContext()}, s.limiter, resources)
		}, nil, s.counters)
	}()
	t.Cleanup(func() { s.stop(t) })
	return s
}

func (s *quicTestServer) stop(t *testing.T) {
	t.Helper()
	s.cancel()
	select {
	case <-s.done:
		if s.err != nil {
			t.Errorf("QUIC server stopped with error: %v", s.err)
		}
	case <-time.After(5 * time.Second):
		t.Error("QUIC server did not join its handlers after grace")
		return
	}
	quicWait(t, "QUIC listener/socket release", func() bool {
		return s.counters.Open.Load() == 0 && s.counters.Setup.Load() == 0 && s.resources.Stats().Sockets == 0
	})
}

func quicWait(t *testing.T, what string, ready func() bool) {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for !ready() && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if !ready() {
		t.Errorf("timed out waiting for %s", what)
	}
}

func quicClientResources(t *testing.T) *datagram.Resources {
	t.Helper()
	r := datagram.NewResources(8, 2<<20)
	t.Cleanup(func() {
		r.Close()
		if s := r.Stats(); s.BufferBytes != 0 || s.Sockets != 0 {
			t.Errorf("QUIC client leaked process resources: %+v", s)
		}
	})
	return r
}

func dialQUICTest(t *testing.T, s *quicTestServer, resources *datagram.Resources, fingerprint string) *quicudp.Conn {
	t.Helper()
	tlsConfig, err := quicudp.ClientTLSConfig(s.addr, "localhost", fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := quicudp.Dial(ctx, s.addr, tlsConfig, resources, 250*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return c
}

func authorizeQUICTest(t *testing.T, c *quicudp.Conn, token string) {
	t.Helper()
	if err := tunnel.SendUDPSetup(c, token); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	for _, stage := range []string{"AUTH", "UDP"} {
		if line, err := tunnel.ReadLine(r); err != nil || line != "OK" {
			t.Fatalf("%s response %q: %v", stage, line, err)
		}
	}
	if r.Buffered() != 0 {
		t.Fatal("unexpected reliable data after UDP setup")
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	c.EnableDatagrams()
}

func quicEchoTarget(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65536)
		for {
			n, peer, err := c.ReadFromUDP(b)
			if err != nil {
				return
			}
			if _, err := c.WriteToUDP(b[:n], peer); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		c.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("UDP echo target worker did not exit")
		}
	})
	return c
}

func checkQUICEcho(t *testing.T, c *quicudp.Conn, target *net.UDPConn, size int) {
	t.Helper()
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i * 17)
	}
	want := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "127.0.0.1", Port: uint16(target.LocalAddr().(*net.UDPAddr).Port)}, payload)
	if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := c.WritePacket(want); err != nil {
		t.Fatalf("write %d-byte UDP payload: %v", size, err)
	}
	got, err := c.ReadPacket()
	if err != nil {
		t.Fatalf("read %d-byte UDP payload: %v", size, err)
	}
	defer got.Release()
	if !bytes.Equal(got.Data, want) {
		t.Fatalf("%d-byte UDP echo changed contents/target", size)
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestQUICUDPRealTargetsAndGracefulShutdown(t *testing.T) {
	s := newQUICTestServer(t, 750*time.Millisecond, 2, nil)
	resources := quicClientResources(t)
	c := dialQUICTest(t, s, resources, s.client.CertificateFingerprint)
	authorizeQUICTest(t, c, s.client.AuthToken)
	target := quicEchoTarget(t)
	// Exercise the maximum existing compatibility case before warming QUIC's
	// congestion window, then ordinary and empty application UDP payloads.
	for _, size := range []int{60000, 0, 64, 1400} {
		checkQUICEcho(t, c, target, size)
	}
	quicWait(t, "released UDP setup permit", func() bool {
		return s.counters.Open.Load() == 1 && s.counters.Setup.Load() == 0
	})
	s.cancel()
	checkQUICEcho(t, c, target, 64)
	s.stop(t)
	c.Close()
	if got := resources.Stats().Sockets; got != 0 {
		t.Fatalf("client socket reservation retained: %d", got)
	}
	if stats := s.resources.Stats(); stats.BufferBytes != stats.CachedBytes {
		t.Fatalf("server retained packet ownership after drain: %+v", stats)
	}
}

func TestQUICUDPTokenRotationAndRejection(t *testing.T) {
	for _, tc := range []struct {
		name     string
		token    string
		expires  time.Duration
		accepted bool
	}{
		{"current", "", time.Hour, true},
		{"previous", "previous-token", time.Hour, true},
		{"expired", "previous-token", -time.Second, false},
		{"wrong", "wrong-token", time.Hour, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newQUICTestServer(t, 0, 2, func(cfg *config.ServerConfig) {
				cfg.PreviousAuthTokens = []config.PreviousToken{{Token: "previous-token", ExpiresAt: time.Now().Add(tc.expires)}}
			})
			resources := quicClientResources(t)
			c := dialQUICTest(t, s, resources, s.client.CertificateFingerprint)
			token := tc.token
			if token == "" {
				token = s.client.AuthToken
			}
			if tc.accepted {
				authorizeQUICTest(t, c, token)
				checkQUICEcho(t, c, quicEchoTarget(t), 64)
				return
			}
			if err := tunnel.SendUDPSetup(c, token); err != nil {
				t.Fatal(err)
			}
			if line, err := tunnel.ReadLine(bufio.NewReader(c)); err == nil && line == "OK" {
				t.Fatal("rejected token received AUTH OK")
			}
			quicWait(t, "rejected authentication cleanup", func() bool { return s.counters.Open.Load() == 0 })
			if stats := s.resources.Stats(); stats.Sockets != 1 || stats.BufferBytes != 0 {
				t.Fatalf("rejected auth allocated UDP target resources: %+v", stats)
			}
		})
	}
}

func TestQUICUDPRejectsCONNECTAndWrongPin(t *testing.T) {
	s := newQUICTestServer(t, 0, 2, nil)
	resources := quicClientResources(t)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	c := dialQUICTest(t, s, resources, s.client.CertificateFingerprint)
	if _, err := io.WriteString(c, "AUTH "+s.client.AuthToken+"\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(c)
	if line, err := tunnel.ReadLine(reader); err != nil || line != "OK" {
		t.Fatalf("AUTH response %q: %v", line, err)
	}
	if _, err := io.WriteString(c, "CONNECT "+target.Addr().String()+"\n"); err != nil {
		t.Fatal(err)
	}
	if line, err := tunnel.ReadLine(reader); err == nil && line == "OK" {
		t.Fatal("UDP-only QUIC endpoint accepted CONNECT")
	}
	if err := target.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if accepted, err := target.Accept(); err == nil {
		accepted.Close()
		t.Fatal("rejected QUIC CONNECT dialed its TCP target")
	} else if e, ok := err.(net.Error); !ok || !e.Timeout() {
		t.Fatal(err)
	}
	c.Close()
	tlsConfig, err := quicudp.ClientTLSConfig(s.addr, "localhost", strings.Repeat("0", 64))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	bad, err := quicudp.Dial(ctx, s.addr, tlsConfig, resources, time.Second)
	if err == nil {
		bad.Close()
		t.Fatal("wrong QUIC certificate pin accepted")
	}
	if got := resources.Stats().Sockets; got != 0 {
		t.Fatalf("failed TLS handshake leaked socket reservation: %d", got)
	}
}

func TestQUICUDPAdmissionSharedWithTCP(t *testing.T) {
	s := newQUICTestServer(t, 0, 1, nil)
	tcp, err := net.DialTimeout("tcp", s.tcpAddr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	quicWait(t, "TCP setup occupying shared permit", func() bool { return s.counters.Setup.Load() == 1 })
	resources := quicClientResources(t)
	c := dialQUICTest(t, s, resources, s.client.CertificateFingerprint)
	// The transport handshake can finish, but the same admission limiter must
	// reject AUTH while the TCP entrance holds the only setup permit.
	_, _ = io.WriteString(c, "AUTH "+s.client.AuthToken+"\nUDP\n")
	if line, err := tunnel.ReadLine(bufio.NewReader(c)); err == nil && line == "OK" {
		t.Fatal("QUIC bypassed TCP's shared setup limit")
	}
	quicWait(t, "shared admission rejection", func() bool { return s.counters.Rejected.Load() == 1 })
	if s.counters.Setup.Load() != 1 || s.counters.Open.Load() != 1 {
		t.Fatal("QUIC rejection changed existing TCP permit")
	}
	c.Close()
	tcp.Close()
}

func TestQUICUDPAuthLimitSharedWithTCP(t *testing.T) {
	s := newQUICTestServer(t, 0, 2, nil)
	tlsConfig, err := quicudp.ClientTLSConfig(s.tcpAddr, "localhost", s.client.CertificateFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig.NextProtos = []string{"http/1.1"}
	for i := 0; i < 5; i++ {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", s.tcpAddr, tlsConfig)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			c.Close()
			t.Fatal(err)
		}
		if _, err := io.WriteString(c, "AUTH wrong-token\n"); err != nil {
			c.Close()
			t.Fatal(err)
		}
		if line, err := tunnel.ReadLine(bufio.NewReader(c)); err == nil && line == "OK" {
			c.Close()
			t.Fatal("incorrect TCP token accepted")
		}
		c.Close()
	}
	resources := quicClientResources(t)
	c := dialQUICTest(t, s, resources, s.client.CertificateFingerprint)
	if err := tunnel.SendUDPSetup(c, s.client.AuthToken); err != nil {
		t.Fatal(err)
	}
	if line, err := tunnel.ReadLine(bufio.NewReader(c)); err == nil && line == "OK" {
		t.Fatal("QUIC bypassed source-IP auth lock created by TCP")
	}
	if s.limiter.Limited() == 0 {
		t.Fatal("shared authentication lock was not consulted")
	}
}

func TestQUICUDPDoesNotRelayBeforeAuthentication(t *testing.T) {
	s := newQUICTestServer(t, 0, 2, nil)
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
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
	if err := control.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// Opening a stream is lazy. Sending an incomplete AUTH makes the server
	// accept the connection while leaving its authentication result pending.
	if _, err := io.WriteString(control, "AUTH "); err != nil {
		t.Fatal(err)
	}
	packet := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "127.0.0.1", Port: uint16(target.LocalAddr().(*net.UDPAddr).Port)}, []byte("must not be relayed"))
	fragments, err := quicudp.Fragments(packet, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range fragments {
		if err := q.SendDatagram(fragment); err != nil {
			t.Fatal(err)
		}
	}
	assertNoTargetPacket := func() {
		t.Helper()
		if err := target.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := target.ReadFromUDP(make([]byte, 100)); err == nil {
			t.Fatal("pre-authentication DATAGRAM reached target")
		} else if e, ok := err.(net.Error); !ok || !e.Timeout() {
			t.Fatal(err)
		}
	}
	assertNoTargetPacket()
	if stats := s.resources.Stats(); stats.Sockets != 1 || stats.BufferBytes != 0 {
		t.Fatalf("pre-authentication DATAGRAM allocated target/reassembly resources: %+v", stats)
	}
	if _, err := io.WriteString(control, s.client.AuthToken+"\nUDP\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(control)
	for i := 0; i < 2; i++ {
		if line, err := tunnel.ReadLine(reader); err != nil || line != "OK" {
			t.Fatalf("AUTH/UDP response %q: %v", line, err)
		}
	}
	// Previously discarded data must not be retained for authenticated replay.
	assertNoTargetPacket()
}

func TestQUICTLSCertificateReloadPreservesUDP(t *testing.T) {
	s := newQUICTestServer(t, 0, 2, nil)
	resources := quicClientResources(t)
	old := dialQUICTest(t, s, resources, s.client.CertificateFingerprint)
	authorizeQUICTest(t, old, s.client.AuthToken)
	target := quicEchoTarget(t)
	checkQUICEcho(t, old, target, 64)
	path := filepath.Join(t.TempDir(), "renewed.json")
	code, err := config.InitializeServer(path, "localhost:9001", ":9001")
	if err != nil {
		t.Fatal(err)
	}
	renewedClient, err := config.DecodeConnection(code)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := config.LoadServerConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	next := *s.cfg
	next.CertFile, next.KeyFile = renewed.CertFile, renewed.KeyFile
	writeReloadConfig(t, s.path, &next)
	if changed, err := s.certs.reload(); err != nil || !changed {
		t.Fatalf("QUIC certificate reload: changed=%v err=%v", changed, err)
	}
	fresh := dialQUICTest(t, s, resources, renewedClient.CertificateFingerprint)
	authorizeQUICTest(t, fresh, s.client.AuthToken)
	checkQUICEcho(t, fresh, target, 64)
	checkQUICEcho(t, old, target, 64)
	tlsConfig, err := quicudp.ClientTLSConfig(s.addr, "localhost", s.client.CertificateFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stale, err := quicudp.Dial(ctx, s.addr, tlsConfig, resources, time.Second)
	if err == nil {
		stale.Close()
		t.Fatal("new QUIC connection accepted stale certificate pin")
	}
}
