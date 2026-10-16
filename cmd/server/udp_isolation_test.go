package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
)

func startUDPIsolationSession(t *testing.T, dial udpDialFunc) (net.Conn, *bufio.Reader) {
	t.Helper()
	server, client := net.Pipe()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		defer server.Close()
		handleUDPTunnelWithDial(server, bufio.NewReader(server), slog.New(slog.NewTextHandler(io.Discard, nil)), time.Now(), 0, func() {}, config.UDPQueueConfig{}, dial)
	}()
	t.Cleanup(func() {
		client.Close()
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("UDP workers leaked after cancellation")
		}
	})
	client.SetDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(client)
	if line, err := tunnel.ReadLine(reader); err != nil || line != "OK" {
		t.Fatalf("setup: %q %v", line, err)
	}
	return client, reader
}

func udpIsolationEcho(t *testing.T) (socks5.UDPDatagram, []byte) {
	t.Helper()
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		b := make([]byte, 1024)
		for {
			n, peer, err := echo.ReadFromUDP(b)
			if err != nil {
				return
			}
			echo.WriteToUDP(b[:n], peer)
		}
	}()
	dst := socks5.UDPDatagram{Host: "127.0.0.1", Port: uint16(echo.LocalAddr().(*net.UDPAddr).Port)}
	return dst, socks5.BuildUDPDatagram(dst, []byte("independent"))
}

func TestUDPSlowDNSDoesNotBlockOtherTargets(t *testing.T) {
	dialer := &net.Dialer{}
	started, canceled := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		if host == "slow.invalid" {
			first := calls.Add(1) == 1
			if first {
				close(started)
			}
			<-ctx.Done()
			if first {
				close(canceled)
			}
			return nil, ctx.Err()
		}
		return dialer.DialContext(ctx, network, address)
	}
	client, reader := startUDPIsolationSession(t, dial)
	_, fast := udpIsolationEcho(t)
	// Establish the fast target before introducing a stuck resolver.
	check := func() {
		t.Helper()
		if err := tunnel.WriteDatagram(client, fast); err != nil {
			t.Fatal(err)
		}
		got, err := tunnel.ReadDatagram(reader)
		if err != nil || !bytes.Equal(got, fast) {
			t.Fatalf("unrelated target blocked: %v", err)
		}
	}
	check()
	slow := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "slow.invalid", Port: 53}, []byte("pending"))
	if err := tunnel.WriteDatagram(client, slow); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("resolver did not start")
	}
	// More packets for the same unresolved target must share the initialization.
	for i := 0; i < 4; i++ {
		if err := tunnel.WriteDatagram(client, slow); err != nil {
			t.Fatal(err)
		}
	}
	check()
	// A new numeric target must work too, while the domain remains unresolved.
	_, another := udpIsolationEcho(t)
	if err := tunnel.WriteDatagram(client, another); err != nil {
		t.Fatal(err)
	}
	if got, err := tunnel.ReadDatagram(reader); err != nil || !bytes.Equal(got, another) {
		t.Fatalf("new IP target blocked: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatal("duplicate target initialization", calls.Load())
	}
	client.Close()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("DNS not canceled")
	}
}

func TestUDPDNSConcurrencyBoundDoesNotBlockIP(t *testing.T) {
	started := make(chan struct{}, udpDNSConcurrency+1)
	dialer := &net.Dialer{}
	var active, peak atomic.Int32
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		if net.ParseIP(host) != nil {
			return dialer.DialContext(ctx, network, address)
		}
		n := active.Add(1)
		defer active.Add(-1)
		for {
			old := peak.Load()
			if n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	client, reader := startUDPIsolationSession(t, dial)
	for i := 0; i < udpDNSConcurrency+8; i++ {
		p := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "slow" + strconv.Itoa(i) + ".invalid", Port: 53}, []byte("wait"))
		if err := tunnel.WriteDatagram(client, p); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < udpDNSConcurrency; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("DNS workers missing")
		}
	}
	_, fast := udpIsolationEcho(t)
	if err := tunnel.WriteDatagram(client, fast); err != nil {
		t.Fatal(err)
	}
	if got, err := tunnel.ReadDatagram(reader); err != nil || !bytes.Equal(got, fast) {
		t.Fatalf("DNS slots blocked IP: %v", err)
	}
	if peak.Load() > udpDNSConcurrency {
		t.Fatal("unbounded DNS concurrency", peak.Load())
	}
}

func TestUDPBlockedWriteDoesNotBlockOtherTargets(t *testing.T) {
	blocked, peer := net.Pipe()
	defer peer.Close()
	started := make(chan struct{})
	dialer := &net.Dialer{}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		if host == "write.invalid" {
			return &udpWriteSignalConn{Conn: blocked, started: started}, nil
		}
		return dialer.DialContext(ctx, network, address)
	}
	client, reader := startUDPIsolationSession(t, dial)
	slow := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "write.invalid", Port: 53}, []byte("blocked"))
	if err := tunnel.WriteDatagram(client, slow); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("write did not start")
	}
	_, fast := udpIsolationEcho(t)
	if err := tunnel.WriteDatagram(client, fast); err != nil {
		t.Fatal(err)
	}
	if got, err := tunnel.ReadDatagram(reader); err != nil || !bytes.Equal(got, fast) {
		t.Fatalf("blocked write stalled another target: %v", err)
	}
}

type udpWriteSignalConn struct {
	net.Conn
	started chan struct{}
}

func (c *udpWriteSignalConn) Write(p []byte) (int, error) { close(c.started); return c.Conn.Write(p) }
