package main

import (
	"bufio"
	"bytes"
	"context"
	"log/slog"
	"mygotunnel/internal/config"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
	"net"
	"sync"
	"testing"
	"time"
)

type udpBurstReplyConn struct {
	payload           []byte
	remaining         int
	exhausted, closed chan struct{}
	once, sent        sync.Once
}

func (c *udpBurstReplyConn) Read(p []byte) (int, error) {
	if c.remaining > 0 {
		c.remaining--
		return copy(p, c.payload), nil
	}
	c.sent.Do(func() { close(c.exhausted) })
	<-c.closed
	return 0, net.ErrClosed
}
func (c *udpBurstReplyConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *udpBurstReplyConn) Close() error                     { c.once.Do(func() { close(c.closed) }); return nil }
func (c *udpBurstReplyConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *udpBurstReplyConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *udpBurstReplyConn) SetDeadline(time.Time) error      { return nil }
func (c *udpBurstReplyConn) SetReadDeadline(time.Time) error  { return nil }
func (c *udpBurstReplyConn) SetWriteDeadline(time.Time) error { return nil }
func TestUDPFairResponsesPreserveInteractiveProbeBehindBurst(t *testing.T) {
	resources := datagram.NewResources(20, 8<<20)
	defer resources.Close()
	burst := &udpBurstReplyConn{payload: bytes.Repeat([]byte{'B'}, 512), remaining: 600, exhausted: make(chan struct{}), closed: make(chan struct{})}
	probe := &udpBurstReplyConn{payload: []byte("interactive-probe"), remaining: 1, exhausted: make(chan struct{}), closed: make(chan struct{})}
	dial := func(_ context.Context, _, addr string) (net.Conn, error) {
		h, _, _ := net.SplitHostPort(addr)
		if h == "burst.invalid" {
			return burst, nil
		}
		return probe, nil
	}
	a, b := net.Pipe()
	done := make(chan struct{})
	var logs bytes.Buffer
	go func() {
		defer close(done)
		defer a.Close()
		handleUDPTunnelWithDial(a, bufio.NewReader(a), slog.New(slog.NewTextHandler(&logs, nil)), time.Now(), 0, func() {}, config.UDPQueueConfig{}, dial, resources)
	}()
	defer func() { b.Close(); <-done }()
	b.SetDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReader(b)
	if _, err := tunnel.ReadLine(br); err != nil {
		t.Fatal(err)
	}
	send := func(host string) {
		t.Helper()
		if err := tunnel.WriteDatagram(b, socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: host, Port: 53}, []byte("request"))); err != nil {
			t.Fatal(err)
		}
	}
	send("burst.invalid")
	select {
	case <-burst.exhausted:
	case <-time.After(time.Second):
		t.Fatal("burst")
	}
	send("probe.invalid")
	select {
	case <-probe.exhausted:
	case <-time.After(time.Second):
		t.Fatal("probe")
	}
	// The tunnel peer starts reading only after the two target response flows run.
	// No kernel loss is involved: mocked UDP targets delivered every reply to Read.
	received := 0
	probeRank := 0
	b.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	for {
		p, err := tunnel.ReadDatagram(br)
		if err != nil {
			break
		}
		_, body, err := socks5.ParseUDPDatagram(p)
		if err != nil {
			t.Fatal(err)
		}
		received++
		if bytes.Equal(body, probe.payload) {
			probeRank = received
		}
	}
	if probeRank == 0 || probeRank > 34 {
		t.Fatalf("interactive probe rank=%d after %d responses", probeRank, received)
	}
	t.Logf("interactive probe delivered at rank %d, including at most 32 unpreemptible in-flight frames; total replies=%d", probeRank, received)
	b.Close()
	<-done
	t.Log(logs.String())
}
