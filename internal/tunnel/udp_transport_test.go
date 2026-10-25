package tunnel

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"mygotunnel/internal/datagram"
)

type packetTestConn struct {
	net.Conn
	packets  [][]byte
	read     datagram.Packet
	writeErr error
	deadline time.Time
	enabled  bool
}

func (c *packetTestConn) Write([]byte) (int, error)            { panic("datagrams written on reliable stream") }
func (c *packetTestConn) ReadPacket() (datagram.Packet, error) { return c.read, nil }
func (c *packetTestConn) WritePacket(p []byte) error {
	if c.deadline.IsZero() {
		panic("packet write has no blocking deadline")
	}
	if c.writeErr != nil {
		return c.writeErr
	}
	c.packets = append(c.packets, bytes.Clone(p))
	return nil
}
func (c *packetTestConn) SetWriteDeadline(t time.Time) error { c.deadline = t; return nil }
func (c *packetTestConn) EnableDatagrams()                   { c.enabled = true }

func TestPacketTransportKeepsBoundariesOwnershipAndDeadline(t *testing.T) {
	for _, fail := range []bool{false, true} {
		r := datagram.NewResources(1, 1<<20)
		q := datagram.NewQueue(64, 1<<20, time.Second, nil, r)
		c := new(packetTestConn)
		wantErr := errors.New("blocked datagram")
		if fail {
			c.writeErr = wantErr
		}
		for i := 0; i < 33; i++ {
			p, err := r.Borrow(16)
			if err != nil {
				t.Fatal(err)
			}
			for j := range p.Data {
				p.Data[j] = byte(i)
			}
			if !q.Push(p) {
				p.Release()
				t.Fatal("queue rejected test packet")
			}
		}
		w := NewDatagramQueueWriter(c, time.Second)
		err := w.WriteQueue(q)
		if fail {
			if !errors.Is(err, wantErr) || w.Stats().Errors != 1 || w.Stats().Calls != 1 {
				t.Fatal(err, w.Stats())
			}
		} else {
			if err != nil || len(c.packets) != 32 || !c.deadline.IsZero() {
				t.Fatal(err, len(c.packets), c.deadline)
			}
			if err := w.WriteQueue(q); err != nil || len(c.packets) != 33 {
				t.Fatal(err, len(c.packets))
			}
			for i, p := range c.packets {
				if !bytes.Equal(p, bytes.Repeat([]byte{byte(i)}, 16)) {
					t.Fatal("packet boundary changed")
				}
			}
			if w.Stats().Calls != 33 {
				t.Fatal(w.Stats())
			}
		}
		q.Close()
		p, err := r.Borrow(16)
		if err != nil {
			t.Fatal(err)
		}
		c.read = p
		reader := NewPacketReader(c, bufio.NewReader(bytes.NewReader(nil)), r)
		got, err := reader.ReadPacket()
		if err != nil || &got.Data[0] != &p.Data[0] {
			t.Fatal("packet reader copied or lost ownership", err)
		}
		got.Release()
		EnableDatagrams(c)
		if !c.enabled {
			t.Fatal("datagram authorization not activated")
		}
		if s := r.Stats(); s.BufferBytes != s.CachedBytes {
			t.Fatal("retained buffer", s)
		}
		r.Close()
	}
}

func TestQueueWriterPreservesTCPBatching(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	r := datagram.NewResources(1, 1<<20)
	defer r.Close()
	q := datagram.NewQueue(32, 1<<20, time.Second, nil, r)
	defer q.Close()
	for _, s := range []string{"first", "second"} {
		p, err := r.Borrow(len(s))
		if err != nil {
			t.Fatal(err)
		}
		copy(p.Data, s)
		if !q.Push(p) {
			p.Release()
			t.Fatal("push")
		}
	}
	done := make(chan error, 1)
	w := NewDatagramQueueWriter(a, time.Second)
	go func() { done <- w.WriteQueue(q) }()
	reader := NewPacketReader(b, bufio.NewReader(b), r)
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	for _, want := range []string{"first", "second"} {
		p, err := reader.ReadPacket()
		if err != nil {
			t.Fatal(err)
		}
		got := string(p.Data)
		p.Release()
		if got != want {
			t.Fatal(got)
		}
	}
	if err := <-done; err != nil || w.Stats().Calls != 1 {
		t.Fatal(err, w.Stats())
	}
}
