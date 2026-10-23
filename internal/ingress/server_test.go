package ingress

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClassificationPreservesOriginalBytes(t *testing.T) {
	for _, input := range []string{
		"GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n",
		"GET /" + strings.Repeat("x", 6000) + " HTTP/1.1\r\nHost: example.invalid\r\n\r\n",
		"AUTH wrong\r\nCONNECT ignored:80\nraw\x00",
		"  AUTH a b  \r\nCONNECT ignored:80\nraw\x00",
		"AUTH " + strings.Repeat("x", 5000) + "\n",
		"AUTH bad\x00value\nGET / HTTP/1.1\r\n\r\n",
		"\u00a0AUTH secret\nUDP\n",
	} {
		r := bufio.NewReader(strings.NewReader(input))
		raw, _, _, err := classify(r)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(io.MultiReader(bytes.NewReader(raw), r))
		if err != nil || string(got) != input {
			t.Fatalf("input replay changed (%d bytes): %v", len(input), err)
		}
	}
	for _, input := range []string{"AUTH x\n", "  AUTH a b \r\n", "\u00a0AUTH x\n", "AUTH " + strings.Repeat("x", 4090) + "\n"} {
		_, _, ok, err := classify(bufio.NewReader(strings.NewReader(input)))
		if err != nil || !ok {
			t.Fatalf("valid legacy AUTH not recognized: %v", err)
		}
	}
}

type readyTLS struct{ net.Conn }

func (readyTLS) HandshakeContext(context.Context) error { return nil }

type pipeSession struct {
	client          net.Conn
	reader          *bufio.Reader
	done            chan struct{}
	setupReleased   atomic.Int32
	preAuthReleased atomic.Int32
}

func newEntry(t *testing.T, maxHTTP int) *Server {
	t.Helper()
	s, err := New([]byte("public page\n"), maxHTTP, 32, 1000, 1000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func openPipe(t *testing.T, s *Server, started time.Time, auth func(string) error) *pipeSession {
	t.Helper()
	a, b := net.Pipe()
	p := &pipeSession{client: b, reader: bufio.NewReader(b), done: make(chan struct{})}
	if err := b.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(p.done)
		defer a.Close()
		r, _ := s.Route(context.Background(), readyTLS{a}, started, func() { p.setupReleased.Add(1) }, func() { p.preAuthReleased.Add(1) }, auth)
		if r != nil {
			_, _ = io.Copy(a, r)
		}
	}()
	t.Cleanup(func() {
		b.Close()
		select {
		case <-p.done:
		case <-time.After(2 * time.Second):
			t.Error("route did not stop")
		}
	})
	return p
}

func deny(string) error { return errors.New("credential rejected") }

func (p *pipeSession) request(t *testing.T, method, request string) *http.Response {
	t.Helper()
	if _, err := io.WriteString(p.client, request); err != nil {
		t.Fatal(err)
	}
	r, err := http.ReadResponse(p.reader, &http.Request{Method: method})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func readBody(t *testing.T, r *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Body.Close(); err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestHTTPFallbackNormalRequestsAndKeepAlive(t *testing.T) {
	s := newEntry(t, 4)
	var authCalls atomic.Int32
	p := openPipe(t, s, time.Now(), func(line string) error { authCalls.Add(1); return deny(line) })
	for i, tc := range []struct {
		method, path string
		status       int
		body         string
	}{
		{"GET", "/", 200, "public page\n"}, {"HEAD", "/", 200, ""}, {"GET", "/missing", 404, "Not Found\n"}, {"HEAD", "/missing", 404, ""},
		{"POST", "/", 405, "Method Not Allowed\n"}, {"OPTIONS", "*", 405, "Method Not Allowed\n"}, {"GET", "/", 200, "public page\n"}, {"GET", "/", 200, "public page\n"},
	} {
		r := p.request(t, tc.method, tc.method+" "+tc.path+" HTTP/1.1\r\nHost: arbitrary.invalid\r\n\r\n")
		if r.StatusCode != tc.status || readBody(t, r) != tc.body {
			t.Fatalf("request %d: status=%d", i, r.StatusCode)
		}
		if (i == 7) != r.Close {
			t.Fatalf("request %d: close=%v", i, r.Close)
		}
	}
	<-p.done
	if authCalls.Load() != 0 || p.setupReleased.Load() != 1 || p.preAuthReleased.Load() != 1 {
		t.Fatal("HTTP used authentication or retained setup")
	}
	if s.Metrics.HTTPActive.Load() != 0 || s.Metrics.HTTPRequests.Load() != 8 {
		t.Fatal("HTTP accounting did not settle")
	}
}

func TestRejectedAuthUsesHTTPAndCannotReauthenticate(t *testing.T) {
	s := newEntry(t, 4)
	for _, suffix := range []string{"", "CONNECT ignored.invalid:80\nAUTH correct\nUDP\n"} {
		p := openPipe(t, s, time.Now(), deny)
		r := p.request(t, "AUTH", "AUTH wrong\n"+suffix)
		if r.StatusCode != 400 || !r.Close || strings.Contains(readBody(t, r), "wrong") {
			t.Fatal("rejection did not use generic HTTP error")
		}
		<-p.done
	}
	// A legal HTTP request using the reserved legacy method must still be replayed
	// exactly and is never upgraded after its failed candidate authentication.
	var calls atomic.Int32
	p := openPipe(t, s, time.Now(), func(string) error { calls.Add(1); return deny("") })
	r := p.request(t, "AUTH", "AUTH / HTTP/1.1\r\nHost: arbitrary.invalid\r\n\r\n")
	if r.StatusCode != 405 {
		t.Fatal(r.StatusCode)
	}
	readBody(t, r)
	r = p.request(t, "GET", "GET / HTTP/1.1\r\nHost: arbitrary.invalid\r\nConnection: close\r\n\r\n")
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	readBody(t, r)
	<-p.done
	if calls.Load() != 1 {
		t.Fatal("HTTP branch re-entered AUTH")
	}
}

func TestHTTPBodyDoesNotWaitOrSendContinue(t *testing.T) {
	s := newEntry(t, 2)
	p := openPipe(t, s, time.Now(), deny)
	started := time.Now()
	r := p.request(t, "POST", "POST / HTTP/1.1\r\nHost: example.invalid\r\nContent-Length: 999999\r\nExpect: 100-continue\r\n\r\n")
	if r.StatusCode != 405 || !r.Close {
		t.Fatalf("response: %d close=%v", r.StatusCode, r.Close)
	}
	readBody(t, r)
	select {
	case <-p.done:
	case <-time.After(time.Second):
		t.Fatal("unread body blocked cleanup")
	}
	if time.Since(started) > time.Second {
		t.Fatal("unread body consumed timeout")
	}
}

func TestFallbackCannotRestartEntranceDeadline(t *testing.T) {
	for _, request := range []string{"AUTH / HTTP/1.1\r\n", "GET / HTTP/1.1\r\nHost: example.invalid\r\nX: ", "AUTH incom"} {
		s := newEntry(t, 2)
		p := openPipe(t, s, time.Now().Add(-EntryTimeout+150*time.Millisecond), deny)
		started := time.Now()
		if _, err := io.WriteString(p.client, request); err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(p.reader)
		select {
		case <-p.done:
		case <-time.After(time.Second):
			t.Fatal("deadline restarted in fallback")
		}
		if time.Since(started) > 900*time.Millisecond {
			t.Fatal("entrance deadline was extended")
		}
		if s.Metrics.PreAuthTimeout.Load() != 1 {
			t.Fatal("timeout was not counted exactly once")
		}
	}
}

func TestHTTPCapacityDoesNotBlockAuthorizedTunnel(t *testing.T) {
	s := newEntry(t, 1)
	p := openPipe(t, s, time.Now(), deny)
	r := p.request(t, "GET", "GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n")
	readBody(t, r)
	q := openPipe(t, s, time.Now(), deny)
	_, _ = io.WriteString(q.client, "GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n")
	<-q.done
	if s.Metrics.HTTPCapacityRejected.Load() != 1 {
		t.Fatal("HTTP capacity not enforced")
	}
	a := openPipe(t, s, time.Now(), func(string) error { return nil })
	if _, err := io.WriteString(a.client, "AUTH correct\npayload\x00"); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("OK\npayload\x00"))
	if _, err := io.ReadFull(a.reader, got); err != nil || string(got) != "OK\npayload\x00" {
		t.Fatalf("authorized buffered bytes=%q, %v", got, err)
	}
	if a.preAuthReleased.Load() != 1 {
		t.Fatal("authorized connection retained source slot")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	<-p.done
}

func TestGuardBoundedAtomicFairnessAndRefill(t *testing.T) {
	g := NewGuard(2, 1, 3)
	g.maxPeers = 2
	now := time.Now()
	g.now = func() time.Time { return now }
	a := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 10}
	b := &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 20}
	c := &net.TCPAddr{IP: net.ParseIP("192.0.2.3")}
	r1, ok := g.Acquire(a)
	if !ok {
		t.Fatal("first")
	}
	r2, ok := g.Acquire(a)
	if !ok {
		t.Fatal("second")
	}
	if _, ok := g.Acquire(a); ok {
		t.Fatal("concurrency bypass")
	}
	r1()
	r1()
	if _, ok := g.Acquire(a); ok {
		t.Fatal("rate bypass")
	}
	rb, ok := g.Acquire(b)
	if !ok {
		t.Fatal("other IP starved")
	}
	now = now.Add(2 * time.Minute)
	if _, ok := g.Acquire(c); ok {
		t.Fatal("evicted active peer")
	}
	r2()
	rb()
	now = now.Add(2 * time.Second)
	rc, ok := g.Acquire(c)
	if !ok {
		t.Fatal("expired peers not reclaimed")
	}
	rc()
}

func TestGuardConcurrentAcquireAndRelease(t *testing.T) {
	g := NewGuard(4, 10000, 10000)
	var wg sync.WaitGroup
	var active atomic.Int32
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				if release, ok := g.Acquire(&net.TCPAddr{IP: net.ParseIP("192.0.2.1")}); ok {
					if active.Add(1) > 4 {
						t.Error("per-IP concurrency exceeded")
					}
					active.Add(-1)
					release()
					release()
				}
			}
		}()
	}
	wg.Wait()
	if active.Load() != 0 {
		t.Fatal("active count leaked")
	}
}

func TestBlockedAuthReplyAndShutdownRemainBounded(t *testing.T) {
	s := newEntry(t, 2)
	p := openPipe(t, s, time.Now().Add(-EntryTimeout+100*time.Millisecond), func(string) error { return nil })
	if _, err := io.WriteString(p.client, "AUTH correct\n"); err != nil {
		t.Fatal(err)
	}
	// Intentionally do not read OK; a blocked success reply shares the original deadline.
	select {
	case <-p.done:
	case <-time.After(time.Second):
		t.Fatal("blocked OK escaped entrance deadline")
	}
	if p.preAuthReleased.Load() != 0 {
		t.Fatal("failed OK was reported as successful authorization")
	}
	q := openPipe(t, s, time.Now(), deny)
	if _, err := io.WriteString(q.client, "GET / HTTP/1.1\r\nHost: incomplete"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_ = s.Shutdown(ctx)
	select {
	case <-q.done:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not abort pending HTTP headers")
	}
}
