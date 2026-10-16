package tunnel

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

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
