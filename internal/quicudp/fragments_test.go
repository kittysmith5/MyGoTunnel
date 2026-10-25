package quicudp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"mygotunnel/internal/datagram"
)

func fragmentResources(t *testing.T, limit int) *datagram.Resources {
	t.Helper()
	r := datagram.NewResources(4, limit)
	t.Cleanup(func() {
		r.Close()
		if stats := r.Stats(); stats.BufferBytes != 0 {
			t.Errorf("unreleased payload storage: %+v", stats)
		}
	})
	return r
}

func mustFragments(t *testing.T, packet []byte, id uint32) [][]byte {
	t.Helper()
	f, err := Fragments(packet, id)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFragmentRoundTripReordered(t *testing.T) {
	for _, size := range []int{1, fragmentPayload, fragmentPayload + 1, 60000, MaxPacketSize} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			resources := fragmentResources(t, 1<<20)
			r := NewReassembler(resources, 0)
			defer r.Close()
			want := make([]byte, size)
			for i := range want {
				want[i] = byte(i * 31)
			}
			frames := mustFragments(t, want, 42)
			now := time.Unix(100, 0)
			for i := len(frames) - 1; i >= 0; i-- {
				if len(frames[i]) > WireDatagramSize {
					t.Fatalf("oversize wire frame: %d", len(frames[i]))
				}
				packet, complete, err := r.Push(frames[i], now)
				if err != nil || complete != (i == 0) {
					t.Fatalf("fragment %d: complete=%v err=%v", i, complete, err)
				}
				if complete {
					if !bytes.Equal(packet.Data, want) {
						t.Error("packet contents changed")
					}
					packet.Release()
				}
			}
			// Neither a duplicate final fragment nor all repeated fragments may
			// deliver the same logical packet again within the replay window.
			for _, frame := range frames {
				p, ok, err := r.Push(frame, now)
				p.Release()
				if err != nil || ok {
					t.Fatalf("duplicate delivered: %v %v", ok, err)
				}
			}
		})
	}
}

func TestFragmentsOwnInputAndRejectOversize(t *testing.T) {
	input := bytes.Repeat([]byte{7}, fragmentPayload+1)
	frames := mustFragments(t, input, 1)
	input[0] = 99
	if frames[0][fragmentHeader] != 7 {
		t.Fatal("fragment aliases caller input")
	}
	for _, packet := range [][]byte{nil, make([]byte, MaxPacketSize+1)} {
		if _, err := Fragments(packet, 0); !errors.Is(err, ErrMalformedFragment) {
			t.Fatalf("invalid length %d accepted", len(packet))
		}
	}
}

func TestFragmentScratchMatchesOwnedFrames(t *testing.T) {
	packet := bytes.Repeat([]byte{7}, MaxPacketSize)
	want := mustFragments(t, packet, 123)
	count, err := FragmentCount(len(packet))
	if err != nil || count != len(want) {
		t.Fatal(count, err)
	}
	var scratch [WireDatagramSize]byte
	for i, expected := range want {
		got, err := Fragment(scratch[:0], packet, 123, i)
		if err != nil || !bytes.Equal(got, expected) {
			t.Fatalf("fragment %d changed encoding: %v", i, err)
		}
	}
	for _, size := range []int{-1, 0, MaxPacketSize + 1} {
		if _, err := FragmentCount(size); !errors.Is(err, ErrMalformedFragment) {
			t.Fatalf("invalid count for size %d: %v", size, err)
		}
	}
	for _, index := range []int{-1, count} {
		if _, err := Fragment(scratch[:], packet, 1, index); !errors.Is(err, ErrMalformedFragment) {
			t.Fatalf("invalid fragment index %d: %v", index, err)
		}
	}
	if _, err := Fragment(make([]byte, fragmentHeader), packet, 1, 0); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short scratch accepted: %v", err)
	}
	if _, err := Fragment(scratch[:], nil, 1, 0); !errors.Is(err, ErrMalformedFragment) {
		t.Fatalf("empty packet accepted: %v", err)
	}
	if got := testing.AllocsPerRun(100, func() {
		_, _ = Fragment(scratch[:], packet, 1, 0)
	}); got != 0 {
		t.Fatalf("scratch fragment allocated: %.1f", got)
	}
}

func TestFragmentValidationBeforeAllocation(t *testing.T) {
	valid := mustFragments(t, make([]byte, fragmentPayload+1), 9)[0]
	cases := map[string]func([]byte) []byte{
		"short":               func(b []byte) []byte { return b[:fragmentHeader] },
		"wire oversize":       func(b []byte) []byte { return append(b, 0) },
		"magic":               func(b []byte) []byte { b[0]++; return b },
		"version":             func(b []byte) []byte { b[1]++; return b },
		"zero total":          func(b []byte) []byte { binary.BigEndian.PutUint16(b[6:8], 0); return b },
		"oversize total":      func(b []byte) []byte { binary.BigEndian.PutUint16(b[6:8], 65001); return b },
		"zero count":          func(b []byte) []byte { binary.BigEndian.PutUint16(b[10:12], 0); return b },
		"wrong count":         func(b []byte) []byte { binary.BigEndian.PutUint16(b[10:12], 60); return b },
		"index outside count": func(b []byte) []byte { binary.BigEndian.PutUint16(b[8:10], 2); return b },
		"huge index":          func(b []byte) []byte { binary.BigEndian.PutUint16(b[8:10], 65535); return b },
		"short payload":       func(b []byte) []byte { return b[:len(b)-1] },
		"long final payload": func(b []byte) []byte {
			binary.BigEndian.PutUint16(b[8:10], 1)
			return b
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			resources := fragmentResources(t, 1<<20)
			r := NewReassembler(resources, 0)
			defer r.Close()
			p, ok, err := r.Push(mutate(bytes.Clone(valid)), time.Now())
			p.Release()
			if ok || !errors.Is(err, ErrMalformedFragment) {
				t.Fatalf("malformed frame result: %v %v", ok, err)
			}
			if got := resources.Stats().BufferBytes; got != 0 {
				t.Fatalf("allocated %d bytes for invalid frame", got)
			}
		})
	}
}

func TestFragmentAbsoluteExpiryAndIndependentDelivery(t *testing.T) {
	resources := fragmentResources(t, 1<<20)
	r := NewReassembler(resources, 250*time.Millisecond)
	defer r.Close()
	now := time.Unix(100, 0)
	large := mustFragments(t, bytes.Repeat([]byte{3}, 3000), 1)
	if _, ok, err := r.Push(large[0], now); ok || err != nil {
		t.Fatal(ok, err)
	}
	// A later datagram completes while the first one is missing a fragment.
	small := mustFragments(t, []byte("later"), 2)
	p, ok, err := r.Push(small[0], now.Add(100*time.Millisecond))
	if err != nil || !ok || string(p.Data) != "later" {
		t.Fatal(ok, err)
	}
	p.Release()
	if _, ok, err := r.Push(large[1], now.Add(240*time.Millisecond)); ok || err != nil {
		t.Fatal(ok, err)
	}
	// Subsequent pieces do not extend the original absolute expiry.
	if p, ok, err := r.Push(large[2], now.Add(250*time.Millisecond)); ok || err != nil {
		p.Release()
		t.Fatal(ok, err)
	}
	if len(r.pending) != 0 {
		t.Fatal("expired packet was resurrected by its late fragment")
	}
	if got := r.Stats().ExpiredPackets; got != 1 {
		t.Fatalf("incomplete timeout count: %d", got)
	}
	r.Expire(now.Add(time.Second))
	if got := r.Stats().ExpiredPackets; got != 1 {
		t.Fatalf("expiration counted more than once: %d", got)
	}
	if s := resources.Stats(); s.BufferBytes != s.CachedBytes {
		t.Fatalf("expired buffer still owned: %+v", s)
	}
}

func TestFragmentLimitsAndClose(t *testing.T) {
	resources := fragmentResources(t, 2<<20)
	r := NewReassembler(resources, 0)
	now := time.Now()
	for id := uint32(0); id < maxIncomplete; id++ {
		frame := mustFragments(t, make([]byte, MaxPacketSize), id)[0]
		if _, complete, err := r.Push(frame, now); complete || err != nil {
			t.Fatal(complete, err)
		}
	}
	if len(r.pending) != maxIncomplete || resources.Stats().BufferBytes != maxIncomplete*65536 {
		t.Fatal("incomplete packets not charged to process resources")
	}
	frame := mustFragments(t, make([]byte, MaxPacketSize), 100)[0]
	if _, _, err := r.Push(frame, now); !errors.Is(err, ErrFragmentLimit) {
		t.Fatalf("per-association limit: %v", err)
	}
	// Full incomplete slots still allow already-complete small datagrams.
	small := mustFragments(t, []byte("small"), 101)[0]
	p, ok, err := r.Push(small, now)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	p.Release()
	r.Close()
	r.Close()
	if got := r.Stats().ExpiredPackets; got != 0 {
		t.Fatalf("normal close counted as fragment timeout: %d", got)
	}
	if _, _, err := r.Push(small, now); !errors.Is(err, ErrFragmentLimit) {
		t.Fatal("closed reassembler accepted traffic")
	}
	if s := resources.Stats(); s.BufferBytes != s.CachedBytes {
		t.Fatalf("close leaked ownership: %+v", s)
	}
}

func TestFragmentGlobalBudget(t *testing.T) {
	resources := fragmentResources(t, 65536)
	a := NewReassembler(resources, 0)
	b := NewReassembler(resources, 0)
	defer a.Close()
	defer b.Close()
	now := time.Now()
	frame := mustFragments(t, make([]byte, MaxPacketSize), 1)[0]
	if _, _, err := a.Push(frame, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Push(frame, now); !errors.Is(err, datagram.ErrResourceLimit) {
		t.Fatalf("cross-association budget bypass: %v", err)
	}
	a.Expire(now.Add(defaultMaxAge))
	if _, _, err := b.Push(frame, now); err != nil {
		t.Fatalf("expired resources not reusable: %v", err)
	}
}

func TestFragmentConflictingDuplicate(t *testing.T) {
	resources := fragmentResources(t, 1<<20)
	r := NewReassembler(resources, 0)
	defer r.Close()
	now := time.Now()
	frames := mustFragments(t, make([]byte, 2000), 5)
	if _, _, err := r.Push(frames[0], now); err != nil {
		t.Fatal(err)
	}
	if _, complete, err := r.Push(frames[0], now); complete || err != nil {
		t.Fatal("identical duplicate rejected")
	}
	small := mustFragments(t, []byte("conflicting length"), 5)[0]
	if _, _, err := r.Push(small, now); !errors.Is(err, ErrMalformedFragment) {
		t.Fatal("conflicting packet length accepted")
	}
	bad := bytes.Clone(frames[0])
	bad[len(bad)-1]++
	if _, _, err := r.Push(bad, now); !errors.Is(err, ErrMalformedFragment) {
		t.Fatal("conflicting duplicate accepted")
	}
	if len(r.pending) != 0 {
		t.Fatal("conflicted packet retained")
	}
	if p, ok, err := r.Push(frames[1], now); ok || err != nil {
		p.Release()
		t.Fatal("conflicted packet resurrected")
	}
}

func FuzzFragmentValidation(f *testing.F) {
	frames, _ := Fragments([]byte("seed"), 1)
	f.Add(frames[0])
	f.Add([]byte("Q"))
	f.Fuzz(func(t *testing.T, frame []byte) {
		resources := datagram.NewResources(1, 65536)
		r := NewReassembler(resources, 0)
		p, _, _ := r.Push(frame, time.Unix(100, 0))
		p.Release()
		r.Close()
		resources.Close()
		if s := resources.Stats(); s.BufferBytes != 0 {
			t.Fatal("payload storage leaked")
		}
	})
}
