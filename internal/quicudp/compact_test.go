package quicudp

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"mygotunnel/internal/datagram"
)

func TestCompactNegotiationAndMTU(t *testing.T) {
	for _, tc := range []struct {
		name           string
		server, client []string
		compact        bool
	}{
		{"new peers", Protocols(), Protocols(), true},
		{"old server", []string{ALPN}, Protocols(), false},
		{"old client", Protocols(), []string{ALPN}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newTransportPairProtocols(t, time.Second, tc.server, tc.client)
			if p.client.compact != tc.compact || p.server.compact != tc.compact {
				t.Fatal("ALPN mismatch")
			}
			authorizePair(t, p)
			// Early path-MTU estimates may require v1 fragments. Once PMTUD succeeds,
			// a 1200-byte IPv4 SOCKS payload (1210-byte frame) needs one DATAGRAM.
			// 1400-byte payloads may still require fragments: PMTUD is conservative.
			payload := bytes.Repeat([]byte{42}, 1210)
			deadline := time.Now().Add(5 * time.Second)
			for {
				before := p.client.fragmentEnqueues.Load()
				if err := p.client.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				if err := p.client.WritePacket(payload); err != nil {
					t.Fatal(err)
				}
				if err := p.server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				got, err := p.server.ReadPacket()
				if err != nil {
					t.Fatal(err)
				}
				equal := bytes.Equal(got.Data, payload)
				got.Release()
				if !equal {
					t.Fatal("payload corrupted")
				}
				count := p.client.fragmentEnqueues.Load() - before
				if !tc.compact {
					if count != 2 {
						t.Fatalf("legacy used %d fragments", count)
					}
					break
				}
				if count == 1 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("MTU discovery never enabled a complete frame")
				}
				time.Sleep(20 * time.Millisecond)
			}
			// Large packets still use unchanged v1 reassembly on either ALPN.
			large := bytes.Repeat([]byte{17}, 65000)
			sent := make(chan error, 1)
			go func() { sent <- p.server.WritePacket(large) }()
			got, err := p.client.ReadPacket()
			if err != nil {
				t.Fatal(err)
			}
			equal := bytes.Equal(got.Data, large)
			got.Release()
			if !equal {
				t.Fatal("large payload corrupted")
			}
			if err := <-sent; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCompactReceiveBudgetAndValidation(t *testing.T) {
	resources := datagram.NewResources(2, 262144)
	defer resources.Close()
	r := NewReassembler(resources, time.Second)
	defer r.Close()
	c := &Conn{compact: true, resources: resources}
	for _, frame := range [][]byte{{'P', 2}, append([]byte{'P', 2}, make([]byte, compactWireSize)...), {'P', 3, 1}} {
		p, ok, err := c.decodePacket(r, frame)
		p.Release()
		if ok || !errors.Is(err, ErrMalformedFragment) {
			t.Fatal("invalid compact frame accepted")
		}
	}
	frame := append([]byte{'P', 2}, bytes.Repeat([]byte{8}, 1400)...)
	packet, ok, err := c.decodePacket(r, frame)
	if err != nil || !ok {
		t.Fatal(err)
	}
	if resources.Stats().BufferBytes == resources.Stats().CachedBytes {
		t.Fatal("payload not charged")
	}
	frame[2] = 9
	if packet.Data[0] != 8 {
		t.Fatal("payload aliases receive storage")
	}
	packet.Release()
	c.compact = false
	p, ok, err := c.decodePacket(r, frame)
	p.Release()
	if ok || !errors.Is(err, ErrMalformedFragment) {
		t.Fatal("legacy accepted compact frame")
	}
	if resources.Stats().BufferBytes != resources.Stats().CachedBytes {
		t.Fatal("payload leaked")
	}
}
