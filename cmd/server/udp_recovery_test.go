package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
)

func startUDPRecoverySession(t *testing.T, dial udpDialFunc, resources *datagram.Resources) (net.Conn, *bufio.Reader) {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		handleUDPTunnelWithDial(server, bufio.NewReader(server), slog.New(slog.NewTextHandler(io.Discard, nil)), time.Now(), 0, func() {}, config.UDPQueueConfig{}, dial, resources)
	}()
	t.Cleanup(func() {
		client.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("UDP target recovery workers did not stop")
		}
		if s := resources.Stats(); s.Sockets != 0 || s.BufferBytes != s.CachedBytes {
			t.Errorf("target recovery leaked resources: %+v", s)
		}
	})
	client.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(client)
	if line, err := tunnel.ReadLine(reader); err != nil || line != "OK" {
		t.Fatalf("UDP setup: %q %v", line, err)
	}
	return client, reader
}

func waitUDPRecoverySockets(t *testing.T, resources *datagram.Resources, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if resources.Stats().Sockets == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("UDP sockets = %d, want %d", resources.Stats().Sockets, want)
}

func TestUDPFullFailedTargetTableImmediatelyAdmitsHealthyTarget(t *testing.T) {
	resources := datagram.NewResources(udpTargetLimit+1, 8<<20)
	t.Cleanup(resources.Close)
	dialer := &net.Dialer{}
	failed := make(chan struct{}, 1)
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(address)
		if host == "127.0.0.2" {
			failed <- struct{}{}
			return nil, errors.New("controlled target dial failure")
		}
		return dialer.DialContext(ctx, network, address)
	}
	client, reader := startUDPRecoverySession(t, dial, resources)
	for i := 0; i < udpTargetLimit; i++ {
		frame := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "127.0.0.2", Port: uint16(i + 1)}, []byte("fail"))
		if err := tunnel.WriteDatagram(client, frame); err != nil {
			t.Fatal(err)
		}
		select {
		case <-failed:
		case <-time.After(time.Second):
			t.Fatalf("target %d did not dial", i)
		}
		waitUDPRecoverySockets(t, resources, 0)
	}
	_, frame := udpIsolationEcho(t)
	client.SetDeadline(time.Now().Add(time.Second))
	if err := tunnel.WriteDatagram(client, frame); err != nil {
		t.Fatal(err)
	}
	if got, err := tunnel.ReadDatagram(reader); err != nil || !bytes.Equal(got, frame) {
		t.Fatalf("healthy target still blocked by failed map entries: %v", err)
	}
}

// The response reader reports failure before Close returns. Holding Close keeps
// the target worker alive while the dispatcher removes its failed map entry.
type udpRecoveryClosingConn struct {
	closing chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *udpRecoveryClosingConn) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (c *udpRecoveryClosingConn) Write(p []byte) (int, error) {
	return len(p), nil
}
func (c *udpRecoveryClosingConn) Close() error {
	c.once.Do(func() { close(c.closing) })
	<-c.release
	return nil
}
func (c *udpRecoveryClosingConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *udpRecoveryClosingConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *udpRecoveryClosingConn) SetDeadline(time.Time) error      { return nil }
func (c *udpRecoveryClosingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *udpRecoveryClosingConn) SetWriteDeadline(time.Time) error { return nil }

func TestUDPRetiredTargetsKeepWorkerSlotsUntilIOStops(t *testing.T) {
	resources := datagram.NewResources(udpTargetLimit+1, 8<<20)
	t.Cleanup(resources.Close)
	connections := make([]*udpRecoveryClosingConn, udpTargetLimit)
	for i := range connections {
		connections[i] = &udpRecoveryClosingConn{closing: make(chan struct{}), release: make(chan struct{})}
	}
	_, healthy := udpIsolationEcho(t)
	dialer := &net.Dialer{}
	healthyDialed := make(chan struct{}, 1)
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, _ := net.SplitHostPort(address)
		if host == "127.0.0.2" {
			n, _ := strconv.Atoi(port)
			return connections[n-1], nil
		}
		healthyDialed <- struct{}{}
		return dialer.DialContext(ctx, network, address)
	}
	client, reader := startUDPRecoverySession(t, dial, resources)
	release := func(c *udpRecoveryClosingConn) {
		select {
		case <-c.release:
		default:
			close(c.release)
		}
	}
	t.Cleanup(func() {
		for _, c := range connections {
			release(c)
		}
	})
	for i, c := range connections {
		frame := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "127.0.0.2", Port: uint16(i + 1)}, []byte("fail"))
		if err := tunnel.WriteDatagram(client, frame); err != nil {
			t.Fatal(err)
		}
		select {
		case <-c.closing:
		case <-time.After(time.Second):
			t.Fatalf("target %d did not reach blocked Close", i)
		}
	}
	if err := tunnel.WriteDatagram(client, healthy); err != nil {
		t.Fatal(err)
	}
	select {
	case <-healthyDialed:
		t.Fatal("failed map cleanup released a live worker slot")
	case <-time.After(100 * time.Millisecond):
	}
	if got := resources.Stats().Sockets; got != udpTargetLimit {
		t.Fatalf("closing targets lost socket reservations: %d", got)
	}
	release(connections[0])
	waitUDPRecoverySockets(t, resources, udpTargetLimit-1)
	client.SetDeadline(time.Now().Add(time.Second))
	if err := tunnel.WriteDatagram(client, healthy); err != nil {
		t.Fatal(err)
	}
	if got, err := tunnel.ReadDatagram(reader); err != nil || !bytes.Equal(got, healthy) {
		t.Fatalf("slot did not recover after target I/O stopped: %v", err)
	}
}
