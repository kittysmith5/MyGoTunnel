package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"mygotunnel/internal/config"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
	"net"
	"strings"
	"testing"
	"time"
)

func TestUDPActiveExpiryReclaimsProcessMemoryWithoutNewFrames(t *testing.T) {
	r := datagram.NewResources(20, 262144)
	defer r.Close()
	started := make(chan struct{}, 3)
	dial := func(ctx context.Context, n, a string) (net.Conn, error) {
		h, _, _ := net.SplitHostPort(a)
		if strings.HasPrefix(h, "slow") {
			started <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return (&net.Dialer{}).DialContext(ctx, n, a)
	}
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer a.Close()
		handleUDPTunnelWithDial(a, bufio.NewReader(a), slog.New(slog.NewTextHandler(io.Discard, nil)), time.Now(), 0, func() {}, config.UDPQueueConfig{}, dial, r)
	}()
	defer func() { b.Close(); <-done }()
	b.SetDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReader(b)
	if _, err := tunnel.ReadLine(br); err != nil {
		t.Fatal(err)
	}
	_, fast := udpIsolationEcho(t)
	check := func() {
		t.Helper()
		b.SetDeadline(time.Now().Add(time.Second))
		if err := tunnel.WriteDatagram(b, fast); err != nil {
			t.Fatal(err)
		}
		if got, err := tunnel.ReadDatagram(br); err != nil || !bytes.Equal(got, fast) {
			t.Fatal("healthy", err)
		}
	}
	check()
	for i := 0; i < 3; i++ {
		p := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: fmt.Sprintf("slow%d.invalid", i), Port: 53}, make([]byte, 32768))
		if err := tunnel.WriteDatagram(b, p); err != nil {
			t.Fatal(err)
		}
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("dns")
		}
	}
	if s := r.Stats(); s.BufferBytes != 262144 || s.CachedBytes != 0 || s.ResidentBytes != 65536 {
		t.Fatal(s)
	}
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		stats := r.Stats()
		if stats.BufferBytes-stats.CachedBytes == 65536 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if stats := r.Stats(); stats.BufferBytes-stats.CachedBytes != 65536 || stats.Sockets != 4 {
		t.Fatal("expired pending buffers were not reclaimed while DNS still blocked", stats)
	}
	check()
	if stats := r.Stats(); stats.MemoryRejected != 0 {
		t.Fatal("healthy frame hit expired process memory", stats)
	}
}
