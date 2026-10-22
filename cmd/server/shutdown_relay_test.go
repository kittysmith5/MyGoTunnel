package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"mygotunnel/internal/admission"
	"mygotunnel/internal/config"
	"mygotunnel/internal/tunnel"
	"mygotunnel/internal/utlsconn"
)

func TestServerHalfClosedRelayHonorsDrainAndForceGrace(t *testing.T) {
	for _, force := range []bool{false, true} {
		t.Run(map[bool]string{false: "drain", true: "force"}[force], func(t *testing.T) {
			certSource := httptest.NewTLSServer(nil)
			certificate := certSource.TLS.Certificates[0]
			certSource.Close()
			server, err := tls.Listen("tcp4", "127.0.0.1:0", serverTLSConfig(certificate))
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			target, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			grace := 200 * time.Millisecond
			if force {
				grace = 40 * time.Millisecond
			}
			metrics := &admission.Counters{}
			serveDone := make(chan error, 1)
			go func() {
				serveDone <- admission.ServeContext(ctx, grace, server, 2, 2, func(conn net.Conn, permit *admission.Permit) {
					handleTunnelContextWithLimiter(ctx, conn, &config.ServerConfig{AuthToken: "shutdown-relay-test"},
						slog.New(slog.NewTextHandler(io.Discard, nil)), permit.Release,
						&serverPoolOptions{idleSlots: make(chan struct{}, 1), resumeSetup: permit.TryAcquire, abortContext: permit.AbortContext()}, nil)
				}, nil, metrics)
			}()
			pin := sha256.Sum256(certificate.Certificate[0])
			dialCtx, dialCancel := context.WithTimeout(context.Background(), time.Second)
			client, err := utlsconn.Dial(dialCtx, server.Addr().String(), "localhost", hex.EncodeToString(pin[:]))
			dialCancel()
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := tunnel.SendSetup(client, "shutdown-relay-test", target.Addr().String()); err != nil {
				t.Fatal(err)
			}
			peer, err := target.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			if err := peer.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cancel(); client.Close(); peer.Close() })
			reader := bufio.NewReader(client)
			for range 2 {
				if line, err := tunnel.ReadLine(reader); err != nil || line != "OK" {
					t.Fatalf("setup response=%q error=%v", line, err)
				}
			}
			if _, err := io.WriteString(client, "request before shutdown"); err != nil {
				t.Fatal(err)
			}
			if err := client.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if got, err := io.ReadAll(peer); err != nil || string(got) != "request before shutdown" {
				t.Fatalf("target request=%q error=%v", got, err)
			}
			started := time.Now()
			cancel()
			if !force {
				const response = "response during grace"
				if _, err := io.WriteString(peer, response); err != nil {
					t.Fatal(err)
				}
				if err := peer.(*net.TCPConn).CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if got, err := io.ReadAll(reader); err != nil || string(got) != response {
					t.Fatalf("grace response=%q error=%v", got, err)
				}
			}
			select {
			case err := <-serveDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("server half-closed relay exceeded force grace")
			}
			if force && time.Since(started) < grace/2 {
				t.Fatal("process cancellation skipped relay grace")
			}
			if metrics.Open.Load() != 0 || metrics.Setup.Load() != 0 {
				t.Fatal("server shutdown retained handlers/permits")
			}
		})
	}
}
