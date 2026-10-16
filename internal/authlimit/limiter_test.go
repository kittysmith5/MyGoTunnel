package authlimit

import (
	"net"
	"testing"
	"time"
)

func TestBoundedFailureWindowAndRecovery(t *testing.T) {
	l := New(2, 3, time.Minute, time.Minute)
	now := time.Now()
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if !l.Allow("peer") {
			t.Fatal("blocked too early")
		}
		l.Failure("peer")
	}
	if l.Allow("peer") {
		t.Fatal("did not block threshold")
	}
	l.Success("valid-peer")
	if !l.Allow("valid-peer") {
		t.Fatal("valid peer blocked")
	}
	now = now.Add(61 * time.Second)
	if !l.Allow("peer") {
		t.Fatal("did not recover after block")
	}
	l.Failure("a")
	l.Failure("b")
	l.Failure("c")
	if len(l.entries) > 2 {
		t.Fatal("state exceeded bound")
	}
	if l.Allow("new") {
		t.Fatal("full state must fail closed")
	}
}
func TestPeerKeyNormalizesIP(t *testing.T) {
	a := &net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 3}
	if got := PeerKey(a); got != "192.0.2.1" {
		t.Fatal(got)
	}
}
