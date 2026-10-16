package tunnel

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"testing"
)

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
