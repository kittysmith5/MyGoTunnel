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
	"testing"
	"time"

	"mygotunnel/internal/admission"
	"mygotunnel/internal/config"
	"mygotunnel/internal/preconnect"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
	"mygotunnel/internal/utlsconn"
)

func TestUDPSessionAdmissionPoolAndGracefulShutdown(t *testing.T) {
	for _, pooled := range []bool{false, true} {
		name := "ordinary"
		if pooled {
			name = "prepared"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "server.json")
			code, err := config.InitializeServer(path, "localhost:9001", ":9001")
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := config.DecodeConnection(code)
			if err != nil {
				t.Fatal(err)
			}
			serverCfg, err := config.LoadServerConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := tls.LoadX509KeyPair(serverCfg.CertFile, serverCfg.KeyFile)
			if err != nil {
				t.Fatal(err)
			}
			listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"},
			})
			if err != nil {
				t.Fatal(err)
			}
			cfg.RemoteAddr = listener.Addr().String()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			counters := &admission.Counters{}
			idleSlots := make(chan struct{}, 1)
			finished := make(chan struct{})
			result := make(chan error, 1)
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			go func() {
				defer close(finished)
				result <- admission.ServeContext(ctx, 200*time.Millisecond, listener, 1, 8, func(c net.Conn, p *admission.Permit) {
					handleTunnelContext(ctx, c, serverCfg, logger, p.Release, &serverPoolOptions{idleSlots: idleSlots, resumeSetup: p.TryAcquire})
				}, nil, counters)
			}()
			t.Cleanup(func() {
				cancel()
				_ = listener.Close()
				select {
				case <-finished:
				case <-time.After(3 * time.Second):
					t.Error("UDP server did not drain its workers")
				}
			})
			setupCtx, stopSetup := context.WithTimeout(context.Background(), 3*time.Second)
			defer stopSetup()
			var conn net.Conn
			var reader *bufio.Reader
			if pooled {
				entry, err := preconnect.Prepare(setupCtx, cfg)
				if err != nil {
					t.Fatal(err)
				}
				conn, reader = entry.Conn, entry.Reader
				if len(idleSlots) != 1 || counters.Setup.Load() != 0 {
					t.Fatal("prepared UDP connection retained setup capacity")
				}
				if err := tunnel.SendUDPAssociate(conn); err != nil {
					t.Fatal(err)
				}
			} else {
				conn, err = utlsconn.Dial(setupCtx, cfg.RemoteAddr, cfg.SNI, cfg.CertificateFingerprint)
				if err != nil {
					t.Fatal(err)
				}
				reader = bufio.NewReader(conn)
				if err := tunnel.SendUDPSetup(conn, cfg.AuthToken); err != nil {
					t.Fatal(err)
				}
				if line, err := tunnel.ReadLine(reader); err != nil || line != "OK" {
					t.Fatalf("AUTH: %q %v", line, err)
				}
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			if line, err := tunnel.ReadLine(reader); err != nil || line != "OK" {
				t.Fatalf("UDP: %q %v", line, err)
			}
			until := time.Now().Add(time.Second)
			for counters.Setup.Load() != 0 && time.Now().Before(until) {
				time.Sleep(time.Millisecond)
			}
			if counters.Setup.Load() != 0 || counters.Open.Load() != 1 || len(idleSlots) != 0 {
				t.Fatal("UDP relay retained setup/idle permit")
			}
			echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			go func() {
				b := make([]byte, 100)
				for {
					n, p, e := echo.ReadFromUDP(b)
					if e != nil {
						return
					}
					_, _ = echo.WriteToUDP(b[:n], p)
				}
			}()
			packet := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "127.0.0.1", Port: uint16(echo.LocalAddr().(*net.UDPAddr).Port)}, []byte("drain"))
			checkEcho := func() {
				t.Helper()
				if err := tunnel.WriteDatagram(conn, packet); err != nil {
					t.Fatal(err)
				}
				got, err := tunnel.ReadDatagram(reader)
				if err != nil || !bytes.Equal(got, packet) {
					t.Fatalf("UDP echo: %v", err)
				}
			}
			checkEcho()
			cancel()
			// Process cancellation starts a grace period, rather than immediately
			// killing an established UDP association.
			checkEcho()
			select {
			case <-finished:
			case <-time.After(3 * time.Second):
				t.Fatal("grace deadline did not stop UDP")
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			if counters.Open.Load() != 0 || counters.Setup.Load() != 0 || len(idleSlots) != 0 {
				t.Fatal("UDP shutdown leaked admission capacity")
			}
		})
	}
}
