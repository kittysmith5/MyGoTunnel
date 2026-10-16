package tunnel

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"mygotunnel/internal/datagram"
)

func TestPooledDatagramReaderAlignmentLimitsAndOwnership(t *testing.T) {
	r := datagram.NewResources(1, 512)
	defer r.Close()
	held, _ := r.Borrow(1)
	var stream bytes.Buffer
	WriteDatagram(&stream, []byte("drop"))
	WriteDatagram(&stream, []byte("keep"))
	reader := NewDatagramReader(bufio.NewReader(&stream), r)
	if _, err := reader.ReadPacket(); !errors.Is(err, datagram.ErrResourceLimit) {
		t.Fatal(err)
	}
	held.Release()
	p, err := reader.ReadPacket()
	if err != nil || string(p.Data) != "keep" {
		t.Fatal("rejected frame desynchronized stream", err)
	}
	p.Release()
	if _, err = reader.ReadPacket(); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}

	for _, frame := range [][]byte{{0}, {0, 0}, {255, 255}, {0, 5, 1, 2}} {
		reader = NewDatagramReader(bufio.NewReader(bytes.NewReader(frame)), r)
		if _, err = reader.ReadPacket(); err == nil {
			t.Fatal("invalid/truncated frame accepted")
		}
	}
	if s := r.Stats(); s.BufferBytes != s.CachedBytes {
		t.Fatal("truncated payload leaked", s)
	}
}

func TestPooledDatagramReaderEOFOnlyAtFrameBoundary(t *testing.T) {
	for _, tc := range []struct {
		name      string
		frame     []byte
		exhausted bool
		want      error
	}{
		{name: "empty", want: io.EOF},
		{name: "half_prefix", frame: []byte{0}, want: io.ErrUnexpectedEOF},
		{name: "missing_body", frame: []byte{0, 5}, want: io.ErrUnexpectedEOF},
		{name: "partial_body", frame: []byte{0, 5, 'x'}, want: io.ErrUnexpectedEOF},
		{name: "exhausted_empty", exhausted: true, want: io.EOF},
		{name: "exhausted_half_prefix", frame: []byte{0}, exhausted: true, want: io.ErrUnexpectedEOF},
		{name: "exhausted_missing_body", frame: []byte{0, 5}, exhausted: true, want: io.ErrUnexpectedEOF},
		{name: "exhausted_partial_body", frame: []byte{0, 5, 'x'}, exhausted: true, want: io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resources := datagram.NewResources(1, 512)
			defer resources.Close()
			var held datagram.Packet
			if tc.exhausted {
				var err error
				held, err = resources.Borrow(1)
				if err != nil {
					t.Fatal(err)
				}
				defer held.Release()
			}
			reader := NewDatagramReader(bufio.NewReader(bytes.NewReader(tc.frame)), resources)
			packet, err := reader.ReadPacket()
			if !errors.Is(err, tc.want) || errors.Is(err, io.EOF) != (tc.want == io.EOF) {
				t.Fatalf("ReadPacket() error = %v, want %v", err, tc.want)
			}
			if packet.Data != nil {
				packet.Release()
				t.Fatal("failed frame returned a packet owner")
			}
			held.Release()
			if s := resources.Stats(); s.BufferBytes != s.CachedBytes {
				t.Fatal("failed frame retained a buffer owner", s)
			}
		})
	}
}

func TestPooledDatagramReaderWarmAllocationsAndMaximum(t *testing.T) {
	r := datagram.NewResources(1, 1<<20)
	defer r.Close()
	var source bytes.Reader
	buffered := bufio.NewReader(&source)
	reader := NewDatagramReader(buffered, r)
	frame := append([]byte{0, 128}, make([]byte, 128)...)
	if n := testing.AllocsPerRun(1000, func() {
		source.Reset(frame)
		buffered.Reset(&source)
		p, err := reader.ReadPacket()
		if err != nil {
			panic(err)
		}
		p.Release()
	}); n != 0 {
		t.Fatalf("pooled read allocated %v times", n)
	}
	var stream bytes.Buffer
	data := bytes.Repeat([]byte{42}, MaxDatagramSize)
	WriteDatagram(&stream, data)
	reader = NewDatagramReader(bufio.NewReader(&stream), r)
	p, err := reader.ReadPacket()
	if err != nil || !bytes.Equal(p.Data, data) {
		t.Fatal("maximum datagram changed", err)
	}
	p.Release()
}

func TestDatagramWriteTimeoutDoesNotLimitIdleOrReads(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	tracked := &deadlineTrackingConn{Conn: a}
	w := NewDatagramWriter(tracked, 20*time.Millisecond)
	started := time.Now()
	if _, err := w.Write([]byte("blocked")); err == nil {
		t.Fatal("blocked write has no deadline")
	} else if e, ok := err.(net.Error); !ok || !e.Timeout() {
		t.Fatal(err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("write recovery too slow")
	}
	time.Sleep(40 * time.Millisecond)
	read := make(chan error, 1)
	go func() { var p [2]byte; _, err := io.ReadFull(b, p[:]); read <- err }()
	if _, err := w.Write([]byte("ok")); err != nil {
		t.Fatal("idle deadline poisoned next write", err)
	}
	if !tracked.writeDeadline.IsZero() {
		t.Fatal("successful write left deadline on idle TLS stream")
	}
	if err := <-read; err != nil {
		t.Fatal(err)
	}
	go func() { _, err := b.Write([]byte("r")); read <- err }()
	var p [1]byte
	if _, err := a.Read(p[:]); err != nil {
		t.Fatal("write deadline affected read", err)
	}
	if err := <-read; err != nil {
		t.Fatal(err)
	}
	if s := w.Stats(); s.Calls != 2 || s.Errors != 1 || s.Timeouts != 1 || s.MaxDuration < 20*time.Millisecond {
		t.Fatal(s)
	}
}

type deadlineTrackingConn struct {
	net.Conn
	writeDeadline time.Time
}

func (c *deadlineTrackingConn) SetWriteDeadline(deadline time.Time) error {
	c.writeDeadline = deadline
	return c.Conn.SetWriteDeadline(deadline)
}

func TestDatagramQueueReleasesManagedPacketOnWriteError(t *testing.T) {
	r := datagram.NewResources(1, 1024)
	defer r.Close()
	q := datagram.NewQueue(2, 1024, time.Second, nil, r)
	q.PushCopy([]byte("one"))
	q.PushCopy([]byte("two"))
	writer := bufio.NewWriterSize(failingDatagramWriter{}, 2)
	if err := WriteDatagramQueue(writer, q); err == nil {
		t.Fatal("write error lost")
	}
	q.Close()
	if s := r.Stats(); s.BufferBytes != s.CachedBytes {
		t.Fatal("write failure leaked owner", s)
	}
}

type failingDatagramWriter struct{}

func (failingDatagramWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func BenchmarkPooledDatagramRead(b *testing.B) {
	r := datagram.NewResources(1, 1<<20)
	defer r.Close()
	frame := append([]byte{4, 176}, make([]byte, 1200)...)
	var source bytes.Reader
	buffered := bufio.NewReader(&source)
	reader := NewDatagramReader(buffered, r)
	source.Reset(frame)
	p, _ := reader.ReadPacket()
	p.Release()
	b.ReportAllocs()
	b.SetBytes(1200)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		source.Reset(frame)
		buffered.Reset(&source)
		p, err := reader.ReadPacket()
		if err != nil {
			b.Fatal(err)
		}
		p.Release()
	}
}
