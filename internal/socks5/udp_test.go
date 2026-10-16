package socks5

import (
	"bytes"
	"testing"
)

func TestUDPDatagramRoundTrip(t *testing.T) {
	want := []byte("dns payload")
	packet := BuildUDPDatagram(UDPDatagram{Host: "example.com", Port: 53}, want)
	destination, payload, err := ParseUDPDatagram(packet)
	if err != nil {
		t.Fatalf("ParseUDPDatagram() error = %v", err)
	}
	if destination != (UDPDatagram{Host: "example.com", Port: 53}) {
		t.Fatalf("destination = %#v", destination)
	}
	if !bytes.Equal(payload, want) {
		t.Fatalf("payload = %q, want %q", payload, want)
	}
}

func TestParseUDPDatagramRejectsFragments(t *testing.T) {
	_, _, err := ParseUDPDatagram([]byte{0, 0, 1, 1})
	if err == nil {
		t.Fatal("ParseUDPDatagram() unexpectedly accepted a fragmented packet")
	}
}
