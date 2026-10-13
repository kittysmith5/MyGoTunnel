package socks5

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestHandshakeNegotiation(t *testing.T) {
	tests := []struct {
		name            string
		input, response []byte
		wantErr         bool
	}{
		{"no auth", []byte{5, 1, 0}, []byte{5, 0}, false},
		{"no auth among methods", []byte{5, 3, 2, 0, 1}, []byte{5, 0}, false},
		{"unsupported methods", []byte{5, 2, 1, 2}, []byte{5, 255}, true},
		{"zero methods", []byte{5, 0}, []byte{5, 255}, true},
		{"invalid version", []byte{4, 1}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			server.SetDeadline(time.Now().Add(time.Second))
			client.SetDeadline(time.Now().Add(time.Second))
			done := make(chan error, 1)
			go func() { done <- Handshake(server) }()
			for _, b := range tt.input {
				if _, err := client.Write([]byte{b}); err != nil {
					t.Fatal(err)
				}
			}
			if tt.response != nil {
				got := make([]byte, len(tt.response))
				if _, err := io.ReadFull(client, got); err != nil {
					t.Fatal(err)
				}
				if string(got) != string(tt.response) {
					t.Fatalf("response = %v, want %v", got, tt.response)
				}
			}
			if err := <-done; (err != nil) != tt.wantErr {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestHandshakeShortPacket(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	server.SetDeadline(time.Now().Add(time.Second))
	client.SetDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() { done <- Handshake(server) }()
	client.Write([]byte{5, 2, 0})
	client.Close()
	if err := <-done; err == nil {
		t.Fatal("short packet accepted")
	}
}
