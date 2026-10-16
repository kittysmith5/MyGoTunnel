package datagram

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"
)

func TestQueueOwnershipLimitsAndBudget(t *testing.T) {
	budget := NewBudget(6)
	a, b := NewQueue(2, 4, DefaultMaxAge, budget), NewQueue(2, 6, DefaultMaxAge, budget)
	defer a.Close()
	defer b.Close()
	data := []byte("abcd")
	if !a.PushCopy(data) {
		t.Fatal("initial enqueue")
	}
	data[0] = 'z'
	if a.PushCopy([]byte("x")) || b.PushCopy([]byte("xyz")) {
		t.Fatal("byte limits ignored")
	}
	if !b.PushCopy([]byte("xy")) {
		t.Fatal("shared budget refused remaining bytes")
	}
	got, ok := a.TryPop()
	if !ok || string(got.Data) != "abcd" {
		t.Fatal("producer buffer retained")
	}
	if !b.Push(got) {
		t.Fatal("dequeue did not release budget")
	}
	if p, ok := b.TryPop(); !ok || string(p.Data) != "xy" {
		t.Fatal("FIFO order lost")
	}
	if p, ok := b.TryPop(); !ok || !p.At.Equal(got.At) {
		t.Fatal("forwarding reset queue age")
	}
	if budget.used.Load() != 0 {
		t.Fatal("budget leaked")
	}
	if a.Stats().FullDrops != 1 || b.Stats().FullDrops != 1 {
		t.Fatal("full drops not counted")
	}
	if !a.PushCopy([]byte("x")) || !a.PushCopy([]byte("y")) || a.PushCopy([]byte("z")) {
		t.Fatal("packet cap ignored")
	}
	a.Close()
	if a.PushCopy([]byte("x")) || a.Stats().Bytes != 0 || budget.used.Load() != 0 {
		t.Fatal("close retained payload or accepted producer")
	}
}

func TestQueueExpirationAndFreshAdmission(t *testing.T) {
	q := NewQueue(1, 10, DefaultMaxAge, nil)
	defer q.Close()
	if !q.PushCopy([]byte("stale")) {
		t.Fatal("enqueue")
	}
	time.Sleep(DefaultMaxAge + 10*time.Millisecond)
	if !q.PushCopy([]byte("fresh")) {
		t.Fatal("stale entry prevented fresh admission")
	}
	if p, ok := q.TryPop(); !ok || !bytes.Equal(p.Data, []byte("fresh")) {
		t.Fatal("stale packet was forwarded")
	}
	if q.Push(Packet{Data: []byte("old"), At: time.Now().Add(-2 * DefaultMaxAge)}) {
		t.Fatal("accepted expired forwarded packet")
	}
	if q.Stats().ExpiredDrops != 2 {
		t.Fatal(q.Stats())
	}
	// Expiration at dequeue must work without a new producer.
	if !q.PushCopy([]byte("stale")) {
		t.Fatal("enqueue")
	}
	time.Sleep(DefaultMaxAge + 10*time.Millisecond)
	if _, ok := q.TryPop(); ok || q.Stats().ExpiredDrops != 3 {
		t.Fatal("dequeue retained expired packet")
	}
}

func TestQueueRejectedCopyDoesNotAllocate(t *testing.T) {
	q := NewQueue(1, 1024, DefaultMaxAge, nil)
	defer q.Close()
	data := make([]byte, 1024)
	q.PushCopy(data)
	if n := testing.AllocsPerRun(100, func() { q.PushCopy(data) }); n != 0 {
		t.Fatalf("full queue allocated %v times", n)
	}
}

func TestQueueConcurrentBudgetAndCancellation(t *testing.T) {
	budget := NewBudget(1024)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			q := NewQueue(8, 1024, DefaultMaxAge, budget)
			defer q.Close()
			for j := 0; j < 100; j++ {
				q.PushCopy(make([]byte, 128))
				q.TryPop()
			}
		}()
	}
	wg.Wait()
	if budget.used.Load() != 0 {
		t.Fatal("shared budget leaked")
	}
	q := NewQueue(1, 1, DefaultMaxAge, nil)
	defer q.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := q.Pop(ctx); ok {
		t.Fatal("canceled pop succeeded")
	}
}

func TestQueueUsesConfiguredAge(t *testing.T) {
	q := NewQueue(1, 10, time.Second, nil)
	defer q.Close()
	if !q.Push(Packet{Data: []byte("live"), At: time.Now().Add(-500 * time.Millisecond)}) {
		t.Fatal("configured age ignored")
	}
	if _, ok := q.TryPop(); !ok {
		t.Fatal("dequeue used default age")
	}
}

func TestQueueCloseWakesIdleConsumer(t *testing.T) {
	q := NewQueue(1, 10, time.Second, nil)
	done := make(chan bool, 1)
	go func() { _, ok := q.Pop(context.Background()); done <- ok }()
	q.Close()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("closed queue returned a packet")
		}
	case <-time.After(time.Second):
		t.Fatal("close stranded consumer")
	}
}
