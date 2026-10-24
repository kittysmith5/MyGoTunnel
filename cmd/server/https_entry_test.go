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
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"mygotunnel/internal/admission"
	"mygotunnel/internal/authlimit"
	"mygotunnel/internal/config"
	"mygotunnel/internal/ingress"
	"mygotunnel/internal/preconnect"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
	"mygotunnel/internal/utlsconn"
)

type entryFixture struct {
	client   config.ClientConfig
	entrance *ingress.Server
	counters *admission.Counters
	limiter  *authlimit.Limiter
	stop     func()
	logs     bytes.Buffer
}

func startEntryFixture(t testing.TB, perIP int, enable ...bool) *entryFixture {
	t.Helper()
	source := httptest.NewTLSServer(nil)
	certificate := source.TLS.Certificates[0]
	source.Close()
	ln, err := tls.Listen("tcp4", "127.0.0.1:0", serverTLSConfig(certificate))
	if err != nil {
		t.Fatal(err)
	}
	entrance, err := ingress.New([]byte("public page\n"), 16, perIP, 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(certificate.Certificate[0])
	f := &entryFixture{client: config.ClientConfig{RemoteAddr: ln.Addr().String(), SNI: "localhost", CertificateFingerprint: hex.EncodeToString(sum[:]), AuthToken: "fixture-only-token"}, entrance: entrance, counters: &admission.Counters{}, limiter: authlimit.New(4096, 5, time.Minute, time.Minute)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	idle := make(chan struct{}, 8)
	logger := slog.New(slog.NewJSONHandler(&f.logs, nil))
	router := entrance
	var gate admission.AcceptGate = entrance.Accept
	if len(enable) != 0 && !enable[0] {
		router = nil
		gate = nil
	}
	go func() {
		done <- admission.ServeContext(ctx, 100*time.Millisecond, ln, 4, 32, func(c net.Conn, p *admission.Permit) {
			handleTunnelContextWithLimiter(ctx, c, &config.ServerConfig{AuthToken: f.client.AuthToken}, logger, p.Release, &serverPoolOptions{idleSlots: idle, resumeSetup: p.TryAcquire, abortContext: p.AbortContext(), entrance: router, releasePreAuth: p.ReleasePreAuth, acceptedAt: p.StartedAt()}, f.limiter)
		}, nil, f.counters, gate)
	}()
	f.stop = sync.OnceFunc(func() {
		cancel()
		_ = entrance.Close()
		if err := <-done; err != nil {
			t.Error(err)
		}
		if f.counters.Open.Load() != 0 || f.counters.Setup.Load() != 0 || entrance.Metrics.PreAuthActive.Load() != 0 || entrance.Metrics.HTTPActive.Load() != 0 {
			t.Error("entrance resources leaked")
		}
	})
	t.Cleanup(f.stop)
	return f
}

func TestHTTPSEntryTLSVersionsALPNAndMalformedHeaders(t *testing.T) {
	f := startEntryFixture(t, 4)
	for _, tc := range []struct {
		version   uint16
		protocols []string
		request   string
		status    int
	}{
		{tls.VersionTLS12, []string{"http/1.1"}, "GET / HTTP/1.1\r\nHost: example.invalid\r\nConnection: close\r\n\r\n", 200},
		{tls.VersionTLS13, nil, "HEAD / HTTP/1.1\r\nHost: example.invalid\r\nConnection: close\r\n\r\n", 200},
		{tls.VersionTLS13, []string{"http/1.1"}, "GET / HTTP/1.1\r\nHost: example.invalid\r\nX: " + strings.Repeat("x", 25<<10) + "\r\n\r\n", 431},
		{tls.VersionTLS13, []string{"http/1.1"}, "POST / HTTP/1.1\r\nHost: example.invalid\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n", 400},
		{tls.VersionTLS13, []string{"h2"}, "", 0},
	} {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", f.client.RemoteAddr, &tls.Config{
			MinVersion: tc.version, MaxVersion: tc.version, NextProtos: tc.protocols, ServerName: "unmatched.invalid", InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
				if hex.EncodeToString(sum[:]) != f.client.CertificateFingerprint {
					return errors.New("test certificate mismatch")
				}
				return nil
			},
		})
		if tc.status == 0 {
			if err == nil {
				c.Close()
				t.Fatal("unsupported ALPN accepted")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err = io.WriteString(c, tc.request); err != nil {
			t.Fatal(err)
		}
		method := strings.SplitN(tc.request, " ", 2)[0]
		r, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: method})
		if err != nil {
			t.Fatal(err)
		}
		if r.StatusCode != tc.status {
			t.Fatalf("want %d got %d", tc.status, r.StatusCode)
		}
		_, _ = io.Copy(io.Discard, r.Body)
		r.Body.Close()
		c.Close()
	}
}

// Measures the real local uTLS/TLS/AUTH/CONNECT path in one process, including
// allocations from both ends. It is not a public-network latency benchmark.
func BenchmarkHTTPSEntryColdSetup(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		name := "legacy"
		if enabled {
			name = "https"
		}
		b.Run(name, func(b *testing.B) {
			f := startEntryFixture(b, 4, enabled)
			target, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			defer target.Close()
			var workers sync.WaitGroup
			acceptDone := make(chan struct{})
			go func() {
				defer close(acceptDone)
				for {
					c, err := target.Accept()
					if err != nil {
						return
					}
					workers.Add(1)
					go func() { defer workers.Done(); defer c.Close(); _, _ = io.Copy(io.Discard, c) }()
				}
			}()
			defer func() { target.Close(); <-acceptDone; workers.Wait() }()
			durations := make([]time.Duration, 0, b.N)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				started := time.Now()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				c, err := utlsconn.Dial(ctx, f.client.RemoteAddr, f.client.SNI, f.client.CertificateFingerprint)
				cancel()
				if err != nil {
					b.Fatal(err)
				}
				_ = c.SetDeadline(time.Now().Add(time.Second))
				if err := tunnel.SendSetup(c, f.client.AuthToken, target.Addr().String()); err != nil {
					b.Fatal(err)
				}
				r := bufio.NewReader(c)
				for range 2 {
					line, err := tunnel.ReadLine(r)
					if err != nil || line != "OK" {
						b.Fatalf("setup failed: %q %v", line, err)
					}
				}
				durations = append(durations, time.Since(started))
				_ = c.(interface{ NetConn() net.Conn }).NetConn().Close()
			}
			b.StopTimer()
			sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
			for _, q := range []struct {
				name     string
				fraction float64
			}{{"p50-us", .50}, {"p95-us", .95}, {"p99-us", .99}} {
				b.ReportMetric(float64(durations[min(len(durations)-1, int(float64(len(durations))*q.fraction))].Nanoseconds())/1000, q.name)
			}
		})
	}
}

func (f *entryFixture) dial(t *testing.T) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, _, err := utlsconn.DialWithOptions(ctx, f.client.RemoteAddr, f.client.SNI, f.client.CertificateFingerprint, utlsconn.Options{SessionCache: f.client.TLSSessionCache})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func readOK(t *testing.T, r *bufio.Reader, want string) {
	t.Helper()
	line, err := tunnel.ReadLine(r)
	if err != nil || line != want {
		t.Fatalf("want %s got %q %v", want, line, err)
	}
}

func TestHTTPSEntryRealUTLSFreshPreparedAndHalfClose(t *testing.T) {
	f := startEntryFixture(t, 4)
	for _, mode := range []string{"fresh", "legacy", "ack"} {
		t.Run(mode, func(t *testing.T) {
			target, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			done := make(chan error, 1)
			go func() {
				peer, err := target.Accept()
				if err != nil {
					done <- err
					return
				}
				defer peer.Close()
				_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
				b, err := io.ReadAll(peer)
				if err == nil && string(b) != "payload\x00\n" {
					err = io.ErrUnexpectedEOF
				}
				if err == nil {
					_, err = io.WriteString(peer, "response after FIN\x00\n")
				}
				done <- err
			}()
			var c net.Conn
			var r *bufio.Reader
			if mode == "fresh" {
				c = f.dial(t)
				r = bufio.NewReader(c)
				if _, err := io.WriteString(c, "AUTH "+f.client.AuthToken+"\nCONNECT "+target.Addr().String()+"\npayload\x00\n"); err != nil {
					t.Fatal(err)
				}
				readOK(t, r, "OK")
				readOK(t, r, "OK")
			} else {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				var e *preconnect.Entry
				if mode == "legacy" {
					e, err = preconnect.Prepare(ctx, &f.client)
				} else {
					e, err = preconnect.NewPreparer(&f.client)(ctx)
				}
				if err != nil {
					t.Fatal(err)
				}
				c = e.Conn
				r = e.Reader
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				if err := tunnel.SendConnect(c, target.Addr().String()); err != nil {
					t.Fatal(err)
				}
				if mode == "ack" {
					if !e.CommandACK {
						t.Fatal("ACK not negotiated")
					}
					readOK(t, r, "ACK")
				}
				readOK(t, r, "OK")
				if _, err := io.WriteString(c, "payload\x00\n"); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			b, err := io.ReadAll(r)
			if err != nil || string(b) != "response after FIN\x00\n" {
				t.Fatalf("half-close payload %q %v", b, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHTTPSEntryRealTLSUDP(t *testing.T) {
	f := startEntryFixture(t, 4)
	for _, mode := range []string{"fresh", "legacy", "ack"} {
		t.Run(mode, func(t *testing.T) { testEntryUDP(t, f, mode) })
	}
}

func TestHTTPSEntryResumedSessionsStillAuthenticateAndRelayUDP(t *testing.T) {
	f := startEntryFixture(t, 4)
	f.client.TLSSessionCache = true
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		e, err := preconnect.Prepare(ctx, &f.client)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if e.DialTimings.TLSResumed != (i > 0) {
			t.Fatal("prepared session did not resume")
		}
		e.Conn.(interface{ NetConn() net.Conn }).NetConn().Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, timings, err := utlsconn.DialWithOptions(ctx, f.client.RemoteAddr, f.client.SNI, f.client.CertificateFingerprint, utlsconn.Options{SessionCache: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !timings.TLSResumed {
		t.Fatal("ordinary session did not resume")
	}
	c.SetDeadline(time.Now().Add(2 * time.Second))
	io.WriteString(c, "AUTH wrong\nUDP\n")
	response, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || response.StatusCode != http.StatusBadRequest {
		t.Fatalf("resumed AUTH bypass: %v", err)
	}
	response.Body.Close()
	c.Close()
	for _, mode := range []string{"fresh", "legacy", "ack"} {
		t.Run(mode, func(t *testing.T) { testEntryUDP(t, f, mode) })
	}
}

func testEntryUDP(t *testing.T, f *entryFixture, mode string) {
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		b := make([]byte, 1024)
		n, p, e := echo.ReadFromUDP(b)
		if e == nil {
			_, _ = echo.WriteToUDP(b[:n], p)
		}
	}()
	var c net.Conn
	var r *bufio.Reader
	var setup bytes.Buffer
	if mode == "fresh" {
		c = f.dial(t)
		r = bufio.NewReader(c)
		setup.WriteString("AUTH " + f.client.AuthToken + "\nUDP\n")
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		var e *preconnect.Entry
		if mode == "legacy" {
			e, err = preconnect.Prepare(ctx, &f.client)
		} else {
			e, err = preconnect.NewPreparer(&f.client)(ctx)
		}
		if err != nil {
			t.Fatal(err)
		}
		c, r = e.Conn, e.Reader
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if mode == "ack" && !e.CommandACK {
			t.Fatal("UDP ACK not negotiated")
		}
		setup.WriteString("UDP\n")
	}
	a := echo.LocalAddr().(*net.UDPAddr)
	packet := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "127.0.0.1", Port: uint16(a.Port)}, []byte("UDP payload"))
	// Include the first datagram in the same write as control setup, exercising
	// the shared reader all the way into the UDP frame parser.
	if err := tunnel.WriteDatagram(&setup, packet); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(setup.Bytes()); err != nil {
		t.Fatal(err)
	}
	if mode == "fresh" {
		readOK(t, r, "OK")
	}
	if mode == "ack" {
		readOK(t, r, "ACK")
	}
	readOK(t, r, "OK")
	got, err := tunnel.ReadDatagram(r)
	if err != nil || !bytes.Equal(got, packet) {
		t.Fatalf("UDP payload changed: %v", err)
	}
	c.Close()
}

func TestHTTPSEntryRejectionsAndWebsiteDoNotDialOrPoisonAuth(t *testing.T) {
	f := startEntryFixture(t, 4)
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	request := func(input string, want int) {
		t.Helper()
		c := f.dial(t)
		defer c.Close()
		if _, err := io.WriteString(c, input); err != nil {
			t.Fatal(err)
		}
		r, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		if r.StatusCode != want {
			t.Fatal(r.StatusCode)
		}
		_, _ = io.Copy(io.Discard, r.Body)
		r.Body.Close()
	}
	for range 6 {
		request("GET / HTTP/1.1\r\nHost: arbitrary.invalid\r\nConnection: close\r\n\r\n", 200)
	}
	if !f.limiter.Allow("127.0.0.1") {
		t.Fatal("website poisoned password limiter")
	}
	for range 6 {
		request("AUTH secret-test-value\nCONNECT "+target.Addr().String()+"\n", 400)
	}
	if f.limiter.Allow("127.0.0.1") {
		t.Fatal("bad AUTH failed to block")
	}
	request("AUTH "+f.client.AuthToken+"\nCONNECT "+target.Addr().String()+"\n", 400)
	request("GET / HTTP/1.1\r\nHost: arbitrary.invalid\r\nConnection: close\r\n\r\n", 200)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := preconnect.NewPreparer(&f.client)(ctx); err != tunnel.ErrAuthRejected {
		t.Fatalf("AUTH HTTP rejection caused downgrade: %v", err)
	}
	_ = target.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Millisecond))
	if c, err := target.Accept(); err == nil {
		c.Close()
		t.Fatal("unauthorized target dial")
	}
	f.stop()
	for _, secret := range []string{"secret-test-value", f.client.AuthToken, "arbitrary.invalid"} {
		if strings.Contains(f.logs.String(), secret) {
			t.Fatal("public input leaked in logs")
		}
	}
	if strings.Contains(f.logs.String(), `"msg":"failed"`) {
		t.Fatal("public ingress polluted proxy failure events")
	}
}

func TestHTTPSEntryGatePrecedesGlobalSetup(t *testing.T) {
	f := startEntryFixture(t, 1)
	first, err := net.Dial("tcp4", f.client.RemoteAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	deadline := time.Now().Add(time.Second)
	for f.counters.Setup.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	for range 4 {
		c, err := net.Dial("tcp4", f.client.RemoteAddr)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		if _, err = c.Read(b[:]); err == nil {
			t.Fatal("source concurrency bypass")
		}
		c.Close()
	}
	if f.counters.Setup.Load() != 1 {
		t.Fatal("rejected source consumed global slots")
	}
	d := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
	raw, err := d.Dial("tcp4", f.client.RemoteAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	// This isolated handshake checks admission; the other real uTLS tests verify pins.
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		t.Fatal("another source starved:", err)
	}
	tc.Close()
	first.Close()
}
