package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
)

func TestUDPExpiredSlowQueuesReleaseSharedBudgetBeforeDNSCompletes(t *testing.T) {
	resources := datagram.NewResources(100, 8<<20)
	defer resources.Close()
	started := make(chan struct{}, udpDNSConcurrency)
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		if strings.HasPrefix(host, "slow") {
			started <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	server, client := net.Pipe()
	done := make(chan struct{})
	var logs bytes.Buffer
	go func() {
		defer close(done)
		defer server.Close()
		handleUDPTunnelWithDial(server, bufio.NewReader(server), slog.New(slog.NewTextHandler(&logs, nil)), time.Now(), 0, func() {}, config.UDPQueueConfig{}, dial, resources)
	}()
	t.Cleanup(func() {
		client.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("expiry regression left UDP workers running")
		}
	})
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	if line, err := tunnel.ReadLine(reader); err != nil || line != "OK" {
		t.Fatal(line, err)
	}
	_, fast := udpIsolationEcho(t)
	checkFast := func() {
		t.Helper()
		if err := tunnel.WriteDatagram(client, fast); err != nil {
			t.Fatal(err)
		}
		if got, err := tunnel.ReadDatagram(reader); err != nil || !bytes.Equal(got, fast) {
			t.Fatal("expired slow target queues blocked a healthy target", err)
		}
	}
	checkFast()
	for i := 0; i < udpDNSConcurrency; i++ {
		// Two 32 KiB payloads fill each target's 64 KiB queue. Sixteen targets
		// occupy the default 1 MiB shared budget while their DNS calls wait.
		packet := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: fmt.Sprintf("slow%d.invalid", i), Port: 53}, make([]byte, 32768))
		if err := tunnel.WriteDatagram(client, packet); err != nil {
			t.Fatal(err)
		}
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("slow target did not enter DNS")
		}
		if err := tunnel.WriteDatagram(client, packet); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(3 * datagram.DefaultMaxAge)
	checkFast()
	// All slow DNS workers remain live: recovery comes from expired queues,
	// rather than completion/cancellation of those workers.
	if s := resources.Stats(); s.Sockets != udpDNSConcurrency+1 {
		t.Fatal("test did not keep slow DNS workers alive", s)
	}
	client.Close()
	<-done
	if text := logs.String(); !strings.Contains(text, "queue_full_drops=0") || !strings.Contains(text, "queue_expired_drops=32") || strings.Contains(text, "target_queue_expiry_sweeps=0") {
		t.Fatal(text)
	}
	if s := resources.Stats(); s.Sockets != 0 || s.ResidentBytes != 0 || s.BufferBytes != s.CachedBytes {
		t.Fatal("expiry cleanup leaked resources", s)
	}
}
