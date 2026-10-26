package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"log/slog"
	"mygotunnel/internal/admission"
	"mygotunnel/internal/authlimit"
	"mygotunnel/internal/config"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/quicstream"
	"mygotunnel/internal/quicudp"
	"mygotunnel/internal/tunnel"
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTCPQUICRunsExistingAuthConnectAndHalfClose(t *testing.T) {
	certServer := httptest.NewTLSServer(nil)
	cert := certServer.TLS.Certificates[0]
	certServer.Close()
	resources := datagram.NewResources(16, 8<<20)
	defer resources.Close()
	listener, e := quicstream.Listen("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{quicstream.ALPN}}, resources, 8, 4)
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Shutdown(0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	cfg := &config.ServerConfig{AuthToken: "test-stream-token"}
	limiter := authlimit.New(32, 5, time.Minute, time.Minute)
	go func() {
		done <- admission.ServeContext(ctx, 0, listener, 4, 8, func(c net.Conn, p *admission.Permit) {
			handleTunnelContextWithLimiter(ctx, c, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), p.Release, &serverPoolOptions{abortContext: p.AbortContext()}, limiter, resources)
		}, nil, &admission.Counters{})
	}()
	pin := sha256.Sum256(cert.Certificate[0])
	tc, _ := quicudp.ClientTLSConfig(listener.Addr().String(), "", hex.EncodeToString(pin[:]))
	pool := quicstream.NewPool(listener.Addr().String(), tc, resources)
	defer pool.Close()
	target, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	targetDone := make(chan struct{})
	go func() {
		defer close(targetDone)
		c, e := target.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		body, e := io.ReadAll(c)
		if e == nil {
			c.Write(append([]byte("reply-after-fin:"), body...))
		}
	}()
	probeCtx, probeCancel := context.WithTimeout(context.Background(), time.Second)
	probe, _, e := pool.Open(probeCtx)
	if e != nil {
		t.Fatal(e)
	}
	probe.SetDeadline(time.Now().Add(time.Second))
	tunnel.SendAuth(probe, cfg.AuthToken)
	io.WriteString(probe, "HEALTH\n")
	probeReader := bufio.NewReader(probe)
	for range 2 {
		line, e := tunnel.ReadLine(probeReader)
		if e != nil || line != "OK" {
			t.Fatal("health", line, e)
		}
	}
	probe.Close()
	probeCancel()

	for _, token := range []string{"wrong-token", cfg.AuthToken} {
		requestCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		c, _, e := pool.Open(requestCtx)
		if e != nil {
			stop()
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		r := bufio.NewReader(c)
		if e = tunnel.SendSetup(c, token, target.Addr().String()); e != nil {
			t.Fatal(e)
		}
		line, e := tunnel.ReadLine(r)
		if token != cfg.AuthToken {
			if e != nil || line == "OK" {
				t.Fatal("auth rejection lost", line, e)
			}
			c.Close()
			stop()
			continue
		}
		if e != nil || line != "OK" {
			t.Fatal(line, e)
		}
		line, e = tunnel.ReadLine(r)
		if e != nil || line != "OK" {
			t.Fatal(line, e)
		}
		body := bytes.Repeat([]byte("body"), 20000)
		sent := make(chan error, 1)
		go func() {
			_, e := c.Write(body)
			if e == nil {
				e = c.(*quicstream.Stream).CloseWrite()
			}
			sent <- e
		}()
		response, e := io.ReadAll(r)
		if e != nil || !bytes.Equal(response, append([]byte("reply-after-fin:"), body...)) {
			t.Fatal("stream response truncated", e)
		}
		if e = <-sent; e != nil {
			t.Fatal(e)
		}
		c.Close()
		stop()
	}
	<-targetDone
	cancel()
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}
