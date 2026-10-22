package datagram

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFairQueueAdmitsInteractiveFlowAndReclaimsMetadata(t *testing.T) {
	r := NewResources(1, 1<<20)
	defer r.Close()
	q := NewFairQueue(8, 65000, time.Second, r)
	defer q.Close()
	noisy, probe := q.NewFlow(), q.NewFlow()
	for i := 0; i < 8; i++ {
		if !noisy.PushCopy([]byte{byte(i)}) {
			t.Fatal("noisy fill")
		}
	}
	if !probe.PushCopy([]byte("probe")) {
		t.Fatal("full noisy flow excluded probe")
	}
	noisy.Close()
	probe.Close()
	rank := 0
	for i := 1; i <= 8; i++ {
		p, ok := q.TryPop()
		if !ok {
			t.Fatal("lost packet")
		}
		if string(p.Data) == "probe" {
			rank = i
		}
		p.Release()
	}
	if rank != 2 {
		t.Fatalf("interactive reply rank=%d, want next round", rank)
	}
	s := q.Stats()
	if s.EvictedDrops != 1 || s.FullDrops != 1 || s.Flows != 0 || s.PeakFlows != 2 || s.Bytes != 0 || len(q.largest) != 0 || q.first != nil {
		t.Fatal(s)
	}
	if noisy.PushCopy([]byte("closed")) {
		t.Fatal("closed producer accepted")
	}
	for i := 0; i < 1000; i++ {
		flow := q.NewFlow()
		if !flow.PushCopy([]byte("one")) {
			t.Fatal("flow metadata retained capacity")
		}
		flow.Close()
		p, ok := q.TryPop()
		if !ok {
			t.Fatal("empty")
		}
		p.Release()
	}
	if s := q.Stats(); s.Flows != 0 || s.Packets != 0 {
		t.Fatal(s)
	}
	for _, flow := range q.largest {
		if flow != nil {
			t.Fatal("heap retained drained flow")
		}
	}
	if s := r.Stats(); s.BufferBytes != s.CachedBytes {
		t.Fatal(s)
	}
}
func TestFairQueueBoundsBytesFlowsAndExpiresWithoutConsumer(t *testing.T) {
	r := NewResources(1, 1<<20)
	defer r.Close()
	q := NewFairQueue(4, 65000, time.Second, r)
	defer q.Close()
	large := q.NewFlow()
	if !large.PushCopy(make([]byte, 65000)) {
		t.Fatal("maximum frame")
	}
	small := q.NewFlow()
	if !small.PushCopy([]byte("small")) {
		t.Fatal("large frame monopolized byte budget")
	}
	if s := q.Stats(); s.Bytes != 5 || s.EvictedDrops != 1 || s.Flows != 1 {
		t.Fatal(s)
	}
	if next := q.Expire(time.Now().Add(2 * time.Second)); !next.IsZero() {
		t.Fatal(next)
	}
	if s := q.Stats(); s.ExpiredDrops != 1 || s.Flows != 0 {
		t.Fatal(s)
	}
	flows := make([]*FairFlow, 4)
	for i := range flows {
		flows[i] = q.NewFlow()
		if !flows[i].PushCopy([]byte("x")) {
			t.Fatal(i)
		}
	}
	extra := q.NewFlow()
	if extra.PushCopy([]byte("x")) {
		t.Fatal("equally backlogged flows exceeded packet bound")
	}
	if s := q.Stats(); s.Flows != 4 || s.PeakFlows > 4 || s.Packets != 4 {
		t.Fatal(s)
	}
	q.Close()
	if s := q.Stats(); s.Flows != 0 || s.Bytes != 0 || len(q.largest) != 0 {
		t.Fatal(s)
	}
	for _, flow := range flows {
		if flow.next != nil || flow.prev != nil || flow.heapIndex != -1 {
			t.Fatal("closed queue retained ring/heap links")
		}
	}
	if s := r.Stats(); s.BufferBytes != s.CachedBytes {
		t.Fatal(s)
	}
}
func TestFairQueueConcurrentOwnershipAndWarmReuse(t *testing.T) {
	r := NewResources(1, 1<<20)
	defer r.Close()
	q := NewFairQueue(64, 65000, time.Second, r)
	defer q.Close()
	var producers sync.WaitGroup
	var accepted atomic.Uint64
	done := make(chan struct{})
	var consumed uint64
	for i := 0; i < 16; i++ {
		producers.Add(1)
		go func(id byte) {
			defer producers.Done()
			flow := q.NewFlow()
			defer flow.Close()
			for j := 0; j < 200; j++ {
				data := bytes.Repeat([]byte{id}, 100)
				if flow.PushCopy(data) {
					accepted.Add(1)
				}
				clear(data)
			}
		}(byte(i + 1))
	}
	go func() { producers.Wait(); close(done) }()
	for {
		if p, ok := q.TryPop(); ok {
			if len(p.Data) != 100 || p.Data[0] == 0 || !bytes.Equal(p.Data, bytes.Repeat(p.Data[:1], 100)) {
				t.Fatal("borrowed data corrupted")
			}
			consumed++
			p.Release()
			continue
		}
		select {
		case <-done:
			goto drained
		default:
		}
	}
drained:
	for {
		p, ok := q.TryPop()
		if !ok {
			break
		}
		consumed++
		p.Release()
	}
	if s := q.Stats(); accepted.Load() != consumed+s.EvictedDrops+s.ExpiredDrops || s.Flows != 0 || s.PeakFlows > 64 {
		t.Fatal(accepted.Load(), consumed, s)
	}
	flow := q.NewFlow()
	payload := make([]byte, 1400)
	if allocations := testing.AllocsPerRun(100, func() {
		if !flow.PushCopy(payload) {
			panic("admission")
		}
		p, ok := q.TryPop()
		if !ok {
			panic("dequeue")
		}
		p.Release()
	}); allocations != 0 {
		t.Fatal("warm fair queue allocations", allocations)
	}
}
func BenchmarkFairQueueNoisyInteractive(b *testing.B) {
	for _, mode := range []string{"fifo", "fair"} {
		b.Run(mode, func(b *testing.B) {
			r := NewResources(1, 8<<20)
			defer r.Close()
			payload := make([]byte, 512)
			probe := []byte("probe")
			rankTotal, missed := 0, 0
			var pushNoisy, pushProbe func([]byte) bool
			var pop func() (Packet, bool)
			var closeQueue func()
			if mode == "fifo" {
				q := NewQueue(256, 1<<20, time.Second, nil, r)
				pushNoisy = q.PushCopy
				pushProbe = q.PushCopy
				pop = q.TryPop
				closeQueue = q.Close
			} else {
				q := NewFairQueue(256, 1<<20, time.Second, r)
				n, p := q.NewFlow(), q.NewFlow()
				pushNoisy = n.PushCopy
				pushProbe = p.PushCopy
				pop = q.TryPop
				closeQueue = q.Close
			}
			defer closeQueue()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for j := 0; j < 256; j++ {
					pushNoisy(payload)
				}
				if !pushProbe(probe) {
					missed++
				}
				rank := 0
				for {
					p, ok := pop()
					if !ok {
						break
					}
					rank++
					if bytes.Equal(p.Data, probe) {
						rankTotal += rank
					}
					p.Release()
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(missed)/float64(b.N), "probe_miss/op")
			if missed < b.N {
				b.ReportMetric(float64(rankTotal)/float64(b.N-missed), "probe_rank")
			}
		})
	}
}
func BenchmarkPoolBurst64(b *testing.B) {
	for _, size := range []int{512, 1400, 9000, 65000} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			r := NewResources(128, 64<<20)
			defer r.Close()
			packets := make([]Packet, 64)
			burst := func() {
				for i := range packets {
					p, err := r.Borrow(size)
					if err != nil {
						panic(err)
					}
					packets[i] = p
				}
				for i := range packets {
					packets[i].Release()
				}
			}
			burst()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				burst()
			}
		})
	}
}

func TestFairQueueInteractiveAdmissionReclaimsOwnManagedMemory(t *testing.T) {
	r := NewResources(8, 262144)
	defer r.Close()
	resident, err := r.BorrowResident(65001)
	if err != nil {
		t.Fatal(err)
	}
	defer resident.Release()
	q := NewFairQueue(256, 1<<20, time.Second, r)
	defer q.Close()
	noisy, probe := q.NewFlow(), q.NewFlow()
	for i := 0; i < 3; i++ {
		if !noisy.PushCopy(make([]byte, 65000)) {
			t.Fatal("fill managed memory")
		}
	}
	if s := r.Stats(); s.BufferBytes != s.MemoryLimit || s.CachedBytes != 0 {
		t.Fatal(s)
	}
	if !probe.PushCopy([]byte("interactive")) {
		t.Fatal("logical capacity existed but own hog memory was not reclaimable")
	}
	if s := q.Stats(); s.EvictedDrops != 1 || s.ResourceDrops != 0 || s.Packets != 3 {
		t.Fatal(s)
	}
	q.Close()
	resident.Release()
	if s := r.Stats(); s.BufferBytes != s.CachedBytes || s.PeakBytes > s.MemoryLimit {
		t.Fatal(s)
	}
}
func TestFairQueueDoesNotStealOtherAssociationOwners(t *testing.T) {
	r := NewResources(1, 3*65536)
	defer r.Close()
	held := make([]Packet, 3)
	for i := range held {
		p, err := r.Borrow(65000)
		if err != nil {
			t.Fatal(err)
		}
		held[i] = p
		defer held[i].Release()
	}
	q := NewFairQueue(256, 1<<20, time.Second, r)
	defer q.Close()
	flow := q.NewFlow()
	if flow.PushCopy([]byte("probe")) {
		t.Fatal("bypassed global memory budget")
	}
	if s := q.Stats(); s.ResourceDrops != 1 || s.Flows != 0 || s.EvictedDrops != 0 {
		t.Fatal(s)
	}
	for _, p := range held {
		if len(p.Data) != 65000 {
			t.Fatal("other owner changed")
		}
	}
}
func TestBurstCacheRemainsEvictableUnderMemoryPressure(t *testing.T) {
	r := NewResources(1, 64*2048)
	defer r.Close()
	packets := make([]Packet, 64)
	for i := range packets {
		p, err := r.Borrow(1400)
		if err != nil {
			t.Fatal(err)
		}
		packets[i] = p
	}
	for i := range packets {
		packets[i].Release()
	}
	if s := r.Stats(); s.CachedBytes != 64*2048 {
		t.Fatal("burst working set not retained", s)
	}
	large, err := r.Borrow(65000)
	if err != nil {
		t.Fatal("burst cache blocked another size", err)
	}
	large.Release()
	if s := r.Stats(); s.PeakBytes > s.MemoryLimit || s.BufferBytes != s.CachedBytes || s.CachedBytes != 65536 {
		t.Fatal(s)
	}
	r.Close()
	if s := r.Stats(); s.BufferBytes != 0 {
		t.Fatal(s)
	}
}
func BenchmarkFairQueueSteadyBatch32(b *testing.B) {
	for _, flows := range []int{1, 4} {
		for _, mode := range []string{"fifo", "fair"} {
			b.Run(fmt.Sprintf("%s/%d_flows", mode, flows), func(b *testing.B) {
				r := NewResources(1, 8<<20)
				defer r.Close()
				payload := make([]byte, 1400)
				push := make([]func([]byte) bool, flows)
				var pop func() (Packet, bool)
				var closeQueue func()
				if mode == "fifo" {
					q := NewQueue(256, 1<<20, time.Second, nil, r)
					for i := range push {
						push[i] = q.PushCopy
					}
					pop = q.TryPop
					closeQueue = q.Close
				} else {
					q := NewFairQueue(256, 1<<20, time.Second, r)
					for i := range push {
						f := q.NewFlow()
						push[i] = f.PushCopy
					}
					pop = q.TryPop
					closeQueue = q.Close
				}
				defer closeQueue()
				batch := func() {
					for j := 0; j < 32; j++ {
						if !push[j%flows](payload) {
							panic("admission")
						}
					}
					for j := 0; j < 32; j++ {
						p, ok := pop()
						if !ok {
							panic("dequeue")
						}
						p.Release()
					}
				}
				batch()
				b.ReportAllocs()
				b.SetBytes(32 * 1400)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					batch()
				}
			})
		}
	}
}
