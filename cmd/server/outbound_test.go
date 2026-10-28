package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/dialmetrics"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
)

func TestOutboundIPv4TCP(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "localhost", "::1"} {
		t.Run(host, func(t *testing.T) {
			network, address := "tcp4", "127.0.0.1:0"
			if host == "::1" {
				network, address = "tcp6", "[::1]:0"
			}
			ln, err := net.Listen(network, address)
			if err != nil {
				if host == "::1" {
					t.Skipf("IPv6 loopback unavailable: %v", err)
				}
				t.Fatal(err)
			}
			defer ln.Close()
			echoDone := make(chan struct{})
			go func() {
				defer close(echoDone)
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				b := make([]byte, 4)
				if _, err := io.ReadFull(c, b); err == nil {
					_, _ = c.Write(b)
				}
			}()
			defer func() { ln.Close(); <-echoDone }()
			a, b := net.Pipe()
			done := make(chan struct{})
			go func() {
				defer close(done)
				handleTunnel(a, &config.ServerConfig{AuthToken: "placeholder", OutboundIPFamily: "ipv4"}, slog.New(slog.NewTextHandler(io.Discard, nil)), func() {})
			}()
			defer func() {
				b.Close()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("target handler leaked")
				}
			}()
			_ = b.SetDeadline(time.Now().Add(3 * time.Second))
			target := net.JoinHostPort(host, strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
			if err := tunnel.SendSetup(b, "placeholder", target); err != nil {
				t.Fatal(err)
			}
			r := bufio.NewReader(b)
			if line, err := tunnel.ReadLine(r); err != nil || line != "OK" {
				t.Fatal("AUTH", line, err)
			}
			line, err := tunnel.ReadLine(r)
			if host == "::1" {
				if err != nil || tunnel.ParseConnectResponse(line) == nil {
					t.Fatalf("IPv6 literal was not rejected: %q %v", line, err)
				}
				return
			}
			if err != nil || line != "OK" {
				t.Fatal("CONNECT", line, err)
			}
			if _, err := b.Write([]byte("echo")); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, 4)
			if _, err := io.ReadFull(r, got); err != nil || string(got) != "echo" {
				t.Fatalf("target echo: %q %v", got, err)
			}
		})
	}
}

func TestOutboundIPv4UDPDialWithAndWithoutCache(t *testing.T) {
	for _, cached := range []bool{false, true} {
		target := quicEchoTarget(t)
		cfg := &config.ServerConfig{OutboundIPFamily: "ipv4"}
		var options *serverPoolOptions
		if cached {
			options = &serverPoolOptions{dnsCache: dialmetrics.NewNegativeCache(8, time.Second)}
		}
		dial := targetUDPDial(cfg, options)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		port := strconv.Itoa(target.LocalAddr().(*net.UDPAddr).Port)
		c, err := dial(ctx, "udp", net.JoinHostPort("localhost", port))
		if err != nil {
			t.Fatal(err)
		}
		if c.RemoteAddr().(*net.UDPAddr).IP.To4() == nil {
			t.Fatal("UDP target used IPv6")
		}
		c.Close()
		if c, err := dial(ctx, "udp", net.JoinHostPort("::1", port)); err == nil {
			c.Close()
			t.Fatal("UDP IPv6 literal was accepted")
		}
	}
}

func TestOutboundIPv4UDPBothCarriers(t *testing.T) {
	for _, carrier := range []string{"tcp", "quic"} {
		t.Run(carrier, func(t *testing.T) {
			target := quicEchoTarget(t)
			port := uint16(target.LocalAddr().(*net.UDPAddr).Port)
			bad := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "::1", Port: port}, []byte("blocked"))
			want := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "localhost", Port: port}, []byte("ipv4"))
			var write func([]byte) error
			var read func() ([]byte, error)
			if carrier == "tcp" {
				a, b := net.Pipe()
				done := make(chan struct{})
				go func() {
					defer close(done)
					handleTunnel(a, &config.ServerConfig{AuthToken: "placeholder", OutboundIPFamily: "ipv4"}, slog.New(slog.NewTextHandler(io.Discard, nil)), func() {})
				}()
				t.Cleanup(func() {
					b.Close()
					select {
					case <-done:
					case <-time.After(3 * time.Second):
						t.Error("UDP target workers leaked")
					}
				})
				_ = b.SetDeadline(time.Now().Add(3 * time.Second))
				r := bufio.NewReader(b)
				if err := tunnel.SendUDPSetup(b, "placeholder"); err != nil {
					t.Fatal(err)
				}
				for range 2 {
					if line, err := tunnel.ReadLine(r); err != nil || line != "OK" {
						t.Fatal(line, err)
					}
				}
				write = func(p []byte) error { return tunnel.WriteDatagram(b, p) }
				read = func() ([]byte, error) { return tunnel.ReadDatagram(r) }
			} else {
				s := newQUICTestServer(t, 0, 4, func(cfg *config.ServerConfig) { cfg.OutboundIPFamily = "ipv4" })
				c := dialQUICTest(t, s, quicClientResources(t), s.client.CertificateFingerprint)
				authorizeQUICTest(t, c, s.client.AuthToken)
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				write = c.WritePacket
				read = func() ([]byte, error) {
					p, err := c.ReadPacket()
					if err != nil {
						return nil, err
					}
					defer p.Release()
					return bytes.Clone(p.Data), nil
				}
			}
			// A rejected IPv6 destination must not prevent the same association
			// from resolving and reaching an IPv4 destination.
			for _, packet := range [][]byte{bad, want} {
				if err := write(packet); err != nil {
					t.Fatal(err)
				}
			}
			got, err := read()
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("IPv4 UDP response after IPv6 rejection: %x %v", got, err)
			}
		})
	}
}
