package quicudp

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"mygotunnel/internal/datagram"
)

type retainedPacketQueue interface {
	TryPop() (datagram.Packet, bool)
	TryPopSmallExcept(int, datagram.Packet) (datagram.Packet, bool)
}

// Recreate a producer after its first packet is dequeued but before the sender
// emits the first fragment. This makes the in-flight generation boundary exact.
type afterFirstPopQueue struct {
	retainedPacketQueue
	after func()
	once  sync.Once
}

func (q *afterFirstPopQueue) TryPop() (datagram.Packet, bool) {
	p, ok := q.retainedPacketQueue.TryPop()
	if ok {
		q.once.Do(q.after)
	}
	return p, ok
}

func TestFragmentInterleavePreservesRetainedDestinationOrder(t *testing.T) {
	for _, direction := range []string{"upload", "download"} {
		for _, scenario := range []string{"queued-same-flow", "reaped-key", "replaced-server-flow"} {
			t.Run(direction+"/"+scenario, func(t *testing.T) {
				pair := newTransportPair(t, time.Second)
				authorizePair(t, pair)
				writer, reader := pair.client, pair.server
				if direction == "download" {
					writer, reader = reader, writer
				}
				big := bytes.Repeat([]byte{3}, 65000)
				same := bytes.Repeat([]byte{7}, 64)
				other := bytes.Repeat([]byte{9}, 64)
				var queue retainedPacketQueue
				want := [][]byte{big, same}
				switch scenario {
				case "queued-same-flow":
					q := datagram.NewKeyedQueue(2, 1<<20, time.Second, pair.resources)
					t.Cleanup(q.Close)
					if !q.PushKeyCopy([]byte("same"), big) || !q.PushKeyCopy([]byte("same"), same) {
						t.Fatal("initial packets rejected")
					}
					queue = q
				case "reaped-key":
					q := datagram.NewKeyedQueue(2, 1<<20, time.Second, pair.resources)
					t.Cleanup(q.Close)
					if !q.PushKeyCopy([]byte("same"), big) {
						t.Fatal("initial large packet rejected")
					}
					queue = &afterFirstPopQueue{retainedPacketQueue: q, after: func() {
						// With a two-entry index, these empty destinations force
						// the old in-flight key to be reclaimed before re-admission.
						for _, key := range []string{"first", "second"} {
							if !q.PushKeyCopy([]byte(key), []byte("churn")) {
								t.Error("metadata churn rejected")
							}
							if p, ok := q.TryPop(); ok {
								p.Release()
							}
						}
						if !q.PushKeyCopy([]byte("same"), same) || !q.PushKeyCopy([]byte("other"), other) {
							t.Error("replacement packets rejected")
						}
					}}
					want = [][]byte{other, big, same}
				case "replaced-server-flow":
					q := datagram.NewFairQueue(2, 1<<20, time.Second, pair.resources)
					t.Cleanup(q.Close)
					old := q.NewFlowKey("same")
					if !old.PushCopy(big) {
						t.Fatal("initial response rejected")
					}
					queue = &afterFirstPopQueue{retainedPacketQueue: q, after: func() {
						old.Close()
						if !q.NewFlowKey("same").PushCopy(same) || !q.NewFlowKey("other").PushCopy(other) {
							t.Error("replacement responses rejected")
						}
					}}
					want = [][]byte{other, big, same}
				}
				sent := make(chan error, 1)
				go func() { _, err := writer.WritePacketQueue(queue, time.Second); sent <- err }()
				if err := reader.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				for i, expected := range want {
					p, err := reader.ReadPacket()
					if err != nil {
						t.Fatalf("response %d: %v", i, err)
					}
					matches := bytes.Equal(p.Data, expected)
					p.Release()
					if !matches {
						t.Fatalf("packet %d reordered or corrupted", i)
					}
				}
				if err := <-sent; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
