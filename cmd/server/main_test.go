package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"io"
	"mygotunnel/internal/admission"
	"mygotunnel/internal/authlimit"
	"mygotunnel/internal/config"
	"mygotunnel/internal/preconnect"
	"mygotunnel/internal/tunnel"
	"mygotunnel/internal/utlsconn"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCheckAuth(t *testing.T) {
	tests := []struct {
		name          string
		request       string
		wantResponse  string
		wantErr       bool
		wantErrText   string
		secretNotSeen string
	}{
		{
			name:         "valid token",
			request:      "AUTH expected-token\n",
			wantResponse: "OK\n",
		},
		{
			name:          "wrong token",
			request:       "AUTH secret-value\n",
			wantResponse:  "ERR\n",
			wantErr:       true,
			wantErrText:   "authentication token mismatch",
			secretNotSeen: "secret-value",
		},
		{
			name:         "invalid command",
			request:      "CONNECT example.com:443\n",
			wantResponse: "ERR\n",
			wantErr:      true,
			wantErrText:  "invalid authentication command",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()
			defer clientConn.Close()

			errCh := make(chan error, 1)
			go func() {
				errCh <- checkAuth(serverConn, bufio.NewReader(serverConn), "expected-token")
			}()

			if _, err := io.WriteString(clientConn, tt.request); err != nil {
				t.Fatalf("write authentication request: %v", err)
			}

			response := make([]byte, len(tt.wantResponse))
			if _, err := io.ReadFull(clientConn, response); err != nil {
				t.Fatalf("read authentication response: %v", err)
			}

			err := <-errCh
			if (err != nil) != tt.wantErr {
				t.Fatalf("checkAuth() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got := string(response); got != tt.wantResponse {
				t.Errorf("response = %q, want %q", got, tt.wantResponse)
			}
			if tt.wantErrText != "" && !strings.Contains(err.Error(), tt.wantErrText) {
				t.Errorf("checkAuth() error = %q, want it to contain %q", err, tt.wantErrText)
			}
			if tt.secretNotSeen != "" && strings.Contains(err.Error(), tt.secretNotSeen) {
				t.Errorf("checkAuth() error exposes authentication token: %q", err)
			}
		})
	}
}

type shortDeadlineConn struct {
	net.Conn
	deadlines []time.Time
	timeout   time.Duration
}

func (c *shortDeadlineConn) SetDeadline(deadline time.Time) error {
	c.deadlines = append(c.deadlines, deadline)
	if !deadline.IsZero() {
		timeout := c.timeout
		if timeout == 0 {
			timeout = 100 * time.Millisecond
		}
		deadline = time.Now().Add(timeout)
	}
	return c.Conn.SetDeadline(deadline)
}

func TestCheckAuthTimesOutBlockedReplyAndClearsDeadlines(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	b.SetDeadline(time.Now().Add(time.Second))
	conn := &shortDeadlineConn{Conn: a}
	done := make(chan error, 1)
	go func() { done <- checkAuth(conn, bufio.NewReader(conn), "token") }()
	if _, err := io.WriteString(b, "AUTH token\n"); err != nil {
		t.Fatal(err)
	}
	// Do not read OK: authentication must time out its write as well as its read.
	select {
	case err := <-done:
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("got %v, want timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("authentication reply blocked indefinitely")
	}
	if len(conn.deadlines) != 2 || !conn.deadlines[1].IsZero() {
		t.Fatalf("deadline not cleared: %v", conn.deadlines)
	}
}

func TestHandleTunnelTimesOutMissingCONNECT(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	b.SetDeadline(time.Now().Add(time.Second))
	conn := &shortDeadlineConn{Conn: a}
	done := make(chan struct{})
	go func() {
		handleTunnel(conn, &config.ServerConfig{AuthToken: "token"}, slog.New(slog.NewTextHandler(io.Discard, nil)), func() {})
		close(done)
	}()
	if _, err := io.WriteString(b, "AUTH token\n"); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 3)
	if _, err := io.ReadFull(b, response); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("missing CONNECT blocked indefinitely")
	}
	if len(conn.deadlines) != 3 || conn.deadlines[2].IsZero() {
		t.Fatalf("missing CONNECT deadline: %v", conn.deadlines)
	}
}

func (c *shortDeadlineConn) CloseWrite() error {
	return c.Conn.(interface{ CloseWrite() error }).CloseWrite()
}

func TestHandleTunnelUTLSPreservesPayloadAndClearsDeadlines(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetListener.Close()

	const request = "request\x00\n"
	const response = "response after EOF\x00\n"
	targetDone := make(chan error, 1)
	go func() {
		conn, err := targetListener.Accept()
		if err != nil {
			targetDone <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		payload, err := io.ReadAll(conn)
		if err == nil && string(payload) != request {
			err = fmt.Errorf("target payload = %q", payload)
		}
		if err == nil {
			_, err = io.WriteString(conn, response)
		}
		targetDone <- err
	}()

	serverDone := make(chan *shortDeadlineConn, 1)
	serverErrors := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErrors <- err
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{"http/1.1"},
		})
		tracked := &shortDeadlineConn{Conn: tlsConn, timeout: 2 * time.Second}
		handleTunnel(tracked, &config.ServerConfig{AuthToken: "token"}, slog.New(slog.NewTextHandler(io.Discard, nil)), func() {})
		serverDone <- tracked
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pin := sha256.Sum256(der)
	conn, err := utlsconn.Dial(ctx, listener.Addr().String(), "localhost", hex.EncodeToString(pin[:]))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)
	if err := tunnel.SendAuth(conn, "token"); err != nil {
		t.Fatal(err)
	}
	if line, err := tunnel.ReadLine(reader); err != nil || line != "OK" {
		t.Fatalf("AUTH = %q, %v", line, err)
	}
	// Send CONNECT and binary payload together to exercise buffered handoff.
	if _, err := io.WriteString(conn, "CONNECT "+targetListener.Addr().String()+"\n"+request); err != nil {
		t.Fatal(err)
	}
	if line, err := tunnel.ReadLine(reader); err != nil || line != "OK" {
		t.Fatalf("CONNECT = %q, %v", line, err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(reader)
	if err != nil || string(payload) != response {
		t.Fatalf("response = %q, %v", payload, err)
	}
	select {
	case tracked := <-serverDone:
		if len(tracked.deadlines) != 4 || !tracked.deadlines[1].IsZero() || !tracked.deadlines[3].IsZero() {
			t.Fatalf("deadlines not cleared before relay: %v", tracked.deadlines)
		}
	case err := <-serverErrors:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("server relay did not finish")
	}
	select {
	case err := <-targetDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("target did not finish")
	}
}

func TestPipelinedWrongAuthNeverDialsTarget(t *testing.T) {
	target, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	a, b := net.Pipe()
	defer b.Close()
	b.SetDeadline(time.Now().Add(time.Second))
	done := make(chan struct{})
	go func() {
		handleTunnel(a, &config.ServerConfig{AuthToken: "expected"}, slog.New(slog.NewTextHandler(io.Discard, nil)), func() {})
		close(done)
	}()
	if _, err := io.WriteString(b, "AUTH incorrect\nCONNECT "+target.Addr().String()+"\n"); err != nil {
		t.Fatal(err)
	}
	response, err := tunnel.ReadLine(bufio.NewReader(b))
	if err != nil || response != "ERR" {
		t.Fatalf("response = %q, %v", response, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("auth rejection did not finish")
	}
	target.SetDeadline(time.Now().Add(30 * time.Millisecond))
	conn, err := target.Accept()
	if err == nil {
		conn.Close()
		t.Fatal("authentication failure dialed target")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatal(err)
	}
}

func TestRunRejectsInvalidSetupLimit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := run("unused", logger, -1); err == nil || !strings.Contains(err.Error(), "max-setup") {
		t.Fatal("invalid max-setup accepted")
	}
}

func TestPreparedTLSConnectionIdleAdmissionAndPayload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")
	code, err := config.InitializeServer(path, "localhost:9001", ":9001")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.DecodeConnection(code)
	if err != nil {
		t.Fatal(err)
	}
	server, err := config.LoadServerConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(server.CertFile, server.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cfg.RemoteAddr = listener.Addr().String()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	targetDone := make(chan error, 1)
	go func() {
		c, err := target.Accept()
		if err != nil {
			targetDone <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		data, err := io.ReadAll(c)
		if err == nil && string(data) != "binary\x00\n" {
			err = io.ErrUnexpectedEOF
		}
		if err == nil {
			_, err = io.WriteString(c, "after EOF\x00\n")
		}
		targetDone <- err
	}()
	idleSlots := make(chan struct{}, 1)
	serveDone := make(chan error, 1)
	counters := &admission.Counters{}
	go func() {
		serveDone <- admission.ServeWithMetrics(listener, 1, 8, func(c net.Conn, p *admission.Permit) {
			handleTunnelWithPool(c, server, slog.New(slog.NewTextHandler(io.Discard, nil)), p.Release, &serverPoolOptions{idleSlots: idleSlots, resumeSetup: p.TryAcquire})
		}, nil, counters)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var preparations atomic.Int32
	pool, err := preconnect.New(preconnect.Options{Size: 1}, func(ctx context.Context) (*preconnect.Entry, error) {
		if preparations.Add(1) > 1 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return preconnect.Prepare(ctx, cfg)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var first *preconnect.Entry
	deadline := time.Now().Add(2 * time.Second)
	for first == nil && time.Now().Before(deadline) {
		first = pool.Take(ctx)
		if first == nil {
			time.Sleep(time.Millisecond)
		}
	}
	pool.Close()
	if first == nil {
		t.Fatal("TLS pool did not hand off a prepared connection")
	}
	defer first.Conn.Close()
	// First idle connection released the only setup slot, but consumes idle cap.
	if _, err := preconnect.Prepare(ctx, cfg); !errors.Is(err, preconnect.ErrBusy) {
		t.Fatalf("idle capacity = %v", err)
	}
	// BUSY is written before that handler releases its setup permit.
	// Wait for release rather than racing a legitimate overload rejection.
	for counters.Setup.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if counters.Setup.Load() != 0 {
		t.Fatal("BUSY handler retained setup permit")
	}
	if err := tunnel.SendConnect(first.Conn, target.Addr().String()); err != nil {
		t.Fatal(err)
	}
	response, err := tunnel.ReadLine(first.Reader)
	if err != nil || response != "OK" {
		t.Fatal("prepared CONNECT failed")
	}
	io.WriteString(first.Conn, "binary\x00\n")
	first.Conn.(interface{ CloseWrite() error }).CloseWrite()
	data, err := io.ReadAll(first.Reader)
	if err != nil || string(data) != "after EOF\x00\n" {
		t.Fatalf("prepared response = %q, %v", data, err)
	}
	if err := <-targetDone; err != nil {
		t.Fatal(err)
	}
	// Idle cap was released on CONNECT; another preparation succeeds.
	replacement, err := preconnect.Prepare(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	replacement.Conn.Close()
	listener.Close()
	if err := <-serveDone; err != nil {
		t.Fatal(err)
	}
}

func TestServerTLSConfig(t *testing.T) {
	cfg := serverTLSConfig(tls.Certificate{})
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatal("unexpected minimum TLS version")
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "http/1.1" {
		t.Fatal(cfg.NextProtos)
	}
	if len(cfg.CipherSuites) != 6 {
		t.Fatal("unexpected suite count")
	}
	for _, id := range cfg.CipherSuites {
		switch id {
		case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		default:
			t.Fatalf("non-AEAD/ECDHE suite: %x", id)
		}
	}
}

func TestPreviousAuthTokenAndFailureLimit(t *testing.T) {
	limiter := authlimit.New(16, 2, time.Minute, time.Minute)
	tokens := []string{"new-token", "old-token"}
	authenticate := func(token string) error {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		done := make(chan error, 1)
		go func() { done <- checkAuthTokens(server, bufio.NewReader(server), tokens, limiter, "peer") }()
		_, _ = io.WriteString(client, "AUTH "+token+"\n")
		_, err := tunnel.ReadLine(bufio.NewReader(client))
		if err != nil {
			return err
		}
		return <-done
	}
	if err := authenticate("old-token"); err != nil {
		t.Fatalf("previous token rejected: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := authenticate("bad"); err == nil || err.Error() != "authentication token mismatch" {
			t.Fatalf("bad token: %v", err)
		}
	}
	if err := authenticate("new-token"); !errors.Is(err, authlimit.ErrLimited) {
		t.Fatalf("rate limit not applied: %v", err)
	}
}

func TestPreviousAuthTokenExpiresAtAuthenticationTime(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	cfg := &config.ServerConfig{AuthToken: "new", PreviousAuthTokens: []config.PreviousToken{{Token: "old", ExpiresAt: time.Now().Add(time.Hour)}}}
	now := time.Now()
	done := make(chan error, 1)
	go func() {
		done <- checkAuthTokenProvider(server, bufio.NewReader(server), func() []string { return cfg.ActiveAuthTokens(now) }, nil, "")
	}()
	now = now.Add(2 * time.Hour)
	_, _ = io.WriteString(client, "AUTH old\n")
	reply, err := tunnel.ReadLine(bufio.NewReader(client))
	if err != nil || reply != "ERR" {
		t.Fatalf("reply=%q error=%v", reply, err)
	}
	if err := <-done; err == nil || err.Error() != "authentication token mismatch" {
		t.Fatalf("expired token accepted: %v", err)
	}
}
