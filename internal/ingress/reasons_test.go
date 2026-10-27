package ingress

import (
	"net"
	"testing"
	"time"
)

func TestGuardReasonsKeepAggregateAndPolicy(t *testing.T) {
	g := NewGuard(1, 1, 2)
	g.maxPeers = 1
	now := time.Now()
	g.now = func() time.Time { return now }
	a := &net.TCPAddr{IP: net.ParseIP("192.0.2.1")}
	b := &net.TCPAddr{IP: net.ParseIP("192.0.2.2")}
	r, reason := g.AcquireReason(a)
	if reason != "" {
		t.Fatal(reason)
	}
	if _, reason = g.AcquireReason(a); reason != "concurrency" {
		t.Fatal(reason)
	}
	r()
	if _, reason = g.AcquireReason(a); reason != "rate" {
		t.Fatal(reason)
	}
	if _, reason = g.AcquireReason(b); reason != "table" {
		t.Fatal(reason)
	}
	now = now.Add(2 * time.Second)
	r, reason = g.AcquireReason(a)
	if reason != "" {
		t.Fatal(reason)
	}
	r()
}

type reasonConn struct {
	net.Conn
	addr net.Addr
}

func (c reasonConn) RemoteAddr() net.Addr { return c.addr }
func TestEntranceReasonCountersKeepOriginalTotal(t *testing.T) {
	g := NewGuard(1, 1, 2)
	g.maxPeers = 1
	s := &Server{guard: g}
	a := reasonConn{addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.1")}}
	b := reasonConn{addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.2")}}
	release, ok := s.Accept(a)
	if !ok {
		t.Fatal("first rejected")
	}
	if _, ok = s.Accept(a); ok {
		t.Fatal("concurrency bypass")
	}
	release()
	if _, ok = s.Accept(a); ok {
		t.Fatal("rate bypass")
	}
	if _, ok = s.Accept(b); ok {
		t.Fatal("table bypass")
	}
	if s.Metrics.IPLimited.Load() != 3 || s.Metrics.IPRateLimited.Load() != 1 || s.Metrics.IPConcurrentLimited.Load() != 1 || s.Metrics.IPTableLimited.Load() != 1 || s.Metrics.PreAuthActive.Load() != 0 {
		t.Fatal("reason counters do not match guard decisions")
	}
}
