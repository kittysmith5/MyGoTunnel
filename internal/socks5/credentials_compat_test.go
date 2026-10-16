package socks5

import (
	"io"
	"net"
	"testing"
)

func TestHandshakeWithCredentials(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	errCh := make(chan error, 1)
	go func() { errCh <- HandshakeWithCredentials(server, "client-user", "client-pass", true) }()
	if _, err := client.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
		t.Fatal(err)
	}
	methodReply := make([]byte, 2)
	if _, err := io.ReadFull(client, methodReply); err != nil {
		t.Fatal(err)
	}
	if string(methodReply) != string([]byte{0x05, 0x02}) {
		t.Fatalf("method reply = %v", methodReply)
	}
	request := []byte{0x01, 11}
	request = append(request, "client-user"...)
	request = append(request, 11)
	request = append(request, "client-pass"...)
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	authReply := make([]byte, 2)
	if _, err := io.ReadFull(client, authReply); err != nil {
		t.Fatal(err)
	}
	if authReply[0] != 0x01 || authReply[1] != 0x00 {
		t.Fatalf("authentication reply = %v", authReply)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("HandshakeWithCredentials() error = %v", err)
	}
}

func TestHandshakeWithCredentialsRejectsNoAuthDowngrade(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	errCh := make(chan error, 1)
	go func() { errCh <- HandshakeWithCredentials(server, "user", "pass", true) }()
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0xff {
		t.Fatalf("method reply = %v, want no acceptable method", reply)
	}
	if err := <-errCh; err == nil {
		t.Fatal("HandshakeWithCredentials() unexpectedly accepted no-auth fallback")
	}
}

func TestHandshakeWithCredentialsRejectsWrongPassword(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	errCh := make(chan error, 1)
	go func() { errCh <- HandshakeWithCredentials(server, "user", "expected", true) }()
	if _, err := client.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatal(err)
	}
	methodReply := make([]byte, 2)
	if _, err := io.ReadFull(client, methodReply); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte{0x01, 4, 'u', 's', 'e', 'r', 3, 'b', 'a', 'd'}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0x01 {
		t.Fatalf("authentication reply = %v, want rejection", reply)
	}
	if err := <-errCh; err == nil {
		t.Fatal("HandshakeWithCredentials() unexpectedly accepted incorrect credentials")
	}
}
