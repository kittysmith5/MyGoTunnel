package datagram

import (
	"testing"
	"time"
)

func TestExpireReclaimsSharedBudgetWithoutConsumerProgress(t *testing.T) {
	r := NewResources(1, 4096)
	defer r.Close()
	budget := NewBudget(4)
	one := NewQueue(4, 4, time.Second, budget, r)
	two := NewQueue(4, 4, time.Second, budget, r)
	defer one.Close()
	defer two.Close()
	now := time.Now()
	packet, err := r.Borrow(4)
	if err != nil {
		t.Fatal(err)
	}
	packet.At = now.Add(-500 * time.Millisecond)
	if !one.Push(packet) || budget.CanFit(1) {
		t.Fatal("shared budget was not occupied")
	}
	if next := one.Expire(now); !next.Equal(packet.At.Add(time.Second)) {
		t.Fatal("fresh head expiry changed", next)
	}
	if next := one.Expire(now.Add(600 * time.Millisecond)); !next.IsZero() || !budget.CanFit(4) {
		t.Fatal("expired queue retained shared budget", next)
	}
	if !two.PushCopy([]byte("next")) {
		t.Fatal("other queue could not use reclaimed budget")
	}
	if s := one.Stats(); s.ExpiredDrops != 1 || s.Bytes != 0 || s.Packets != 0 {
		t.Fatal(s)
	}
	one.Close()
	two.Close()
	if s := r.Stats(); s.BufferBytes != s.CachedBytes {
		t.Fatal("expired packet leaked its owner", s)
	}
}
