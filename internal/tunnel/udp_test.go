package tunnel

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestSendUDPSetupPreservesControlValidation(t *testing.T) {
	w := &setupWriter{}
	if err := SendUDPSetup(w, "test-token"); err != nil {
		t.Fatal(err)
	}
	if w.writes != 1 || w.Buffer.String() != "AUTH test-token\nUDP\n" {
		t.Fatal("UDP setup was not one ordered write")
	}
	for _, token := range []string{"", "bad\nUDP", strings.Repeat("x", MaxControlLineBytes)} {
		w = &setupWriter{}
		if err := SendUDPSetup(w, token); err == nil || w.writes != 0 {
			t.Fatal("invalid UDP setup was partly written")
		}
	}
	w = &setupWriter{short: true}
	if err := SendUDPSetup(w, "test-token"); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write error: %v", err)
	}
}

func TestQueuedDatagramsPreserveBoundariesAndFlush(t *testing.T) {
	for _, count := range []int{1, 2, 32, 40} {
		queue := make(chan []byte, count)
		for i := 1; i < count; i++ {
			queue <- []byte{byte(i), 42}
		}
		var wire bytes.Buffer
		writer := bufio.NewWriterSize(&wire, 128)
		if err := WriteQueuedDatagrams(writer, []byte{0, 42}, queue); err != nil {
			t.Fatal(err)
		}
		expected := min(count, 32)
		for i := 0; i < expected; i++ {
			packet, err := ReadDatagram(&wire)
			if err != nil || !bytes.Equal(packet, []byte{byte(i), 42}) {
				t.Fatalf("count %d packet %d: %v, %v", count, i, packet, err)
			}
		}
		if wire.Len() != 0 || writer.Buffered() != 0 || len(queue) != count-expected {
			t.Fatalf("count %d: unexpected buffering or batch size", count)
		}
	}
}

func TestDatagramRoundTrip(t *testing.T) {
	want := []byte{0, 0, 0, 1, 127, 0, 0, 1, 0x1f, 0x90, 1, 2, 3}
	var wire bytes.Buffer
	if err := WriteDatagram(&wire, want); err != nil {
		t.Fatalf("WriteDatagram() error = %v", err)
	}
	got, err := ReadDatagram(&wire)
	if err != nil {
		t.Fatalf("ReadDatagram() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("ReadDatagram() = %v, want %v", got, want)
	}
}

func TestReadDatagramRejectsZeroLength(t *testing.T) {
	_, err := ReadDatagram(bytes.NewReader([]byte{0, 0}))
	if err == nil {
		t.Fatal("ReadDatagram() unexpectedly accepted an empty frame")
	}
}

func TestDatagramSizeLimits(t *testing.T) {
	for _, size := range []int{0, MaxDatagramSize, MaxDatagramSize + 1, 65535} {
		var wire bytes.Buffer
		packet := make([]byte, size)
		wantError := size == 0 || size > MaxDatagramSize
		if err := WriteDatagram(&wire, packet); (err != nil) != wantError {
			t.Fatalf("write size %d: error %v", size, err)
		}
		wire.Reset()
		var header [2]byte
		binary.BigEndian.PutUint16(header[:], uint16(size))
		wire.Write(header[:])
		wire.Write(packet)
		got, err := ReadDatagram(&wire)
		if (err != nil) != wantError || (!wantError && !bytes.Equal(got, packet)) {
			t.Fatalf("read size %d: got %d bytes, error %v", size, len(got), err)
		}
		if wantError && wire.Len() != size {
			t.Fatalf("invalid size %d consumed payload", size)
		}
	}
}

func TestReadDatagramShortFrame(t *testing.T) {
	_, err := ReadDatagram(bytes.NewReader([]byte{0, 3, 1}))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("ReadDatagram() error = %v, want %v", err, io.ErrUnexpectedEOF)
	}
}

type shortDatagramWriter struct {
	bytes.Buffer
}

func (w *shortDatagramWriter) Write(p []byte) (int, error) {
	if len(p) > 3 {
		p = p[:3]
	}
	return w.Buffer.Write(p)
}

func TestDatagramShortWrites(t *testing.T) {
	want := bytes.Repeat([]byte("payload"), 20)
	var wire shortDatagramWriter
	if err := WriteDatagram(&wire, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadDatagram(&wire.Buffer)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("short write round trip: got %d bytes, error %v", len(got), err)
	}
}

func TestBufferedDatagramsAcrossBufferSizes(t *testing.T) {
	for _, size := range []int{1, 2, 3, 16, 32768} {
		var wire bytes.Buffer
		writer := bufio.NewWriterSize(&wire, size)
		for _, n := range []int{1, 13, 1024, MaxDatagramSize} {
			want := bytes.Repeat([]byte{byte(n)}, n)
			if err := WriteDatagram(writer, want); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Flush(); err != nil {
			t.Fatal(err)
		}
		for _, n := range []int{1, 13, 1024, MaxDatagramSize} {
			got, err := ReadDatagram(&wire)
			if err != nil || !bytes.Equal(got, bytes.Repeat([]byte{byte(n)}, n)) {
				t.Fatalf("buffer=%d length=%d: %v", size, n, err)
			}
		}
	}
}

func TestBufferedFramingDoesNotAllocate(t *testing.T) {
	writer := bufio.NewWriterSize(io.Discard, 32768)
	packet := make([]byte, 1024)
	if n := testing.AllocsPerRun(100, func() {
		if err := WriteDatagram(writer, packet); err != nil {
			panic(err)
		}
		if err := writer.Flush(); err != nil {
			panic(err)
		}
	}); n != 0 {
		t.Fatalf("buffered frame allocated %v times", n)
	}
}

func BenchmarkDatagramFraming(b *testing.B) {
	packet := make([]byte, 1024)
	for _, legacy := range []bool{true, false} {
		name := "buffered"
		if legacy {
			name = "previous_frame_copy"
		}
		b.Run(name, func(b *testing.B) {
			writer := bufio.NewWriterSize(io.Discard, 32768)
			b.ReportAllocs()
			b.SetBytes(int64(len(packet)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if legacy {
					frame := make([]byte, 2+len(packet))
					binary.BigEndian.PutUint16(frame[:2], uint16(len(packet)))
					copy(frame[2:], packet)
					if err := writeFull(writer, frame); err != nil {
						b.Fatal(err)
					}
				} else if err := WriteDatagram(writer, packet); err != nil {
					b.Fatal(err)
				}
				if err := writer.Flush(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
