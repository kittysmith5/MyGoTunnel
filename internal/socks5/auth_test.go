package socks5

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestUsernamePasswordAuth(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
		ok      bool
	}{
		{"valid", []byte{1, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's'}, true},
		{"wrong password", []byte{1, 4, 'u', 's', 'e', 'r', 3, 'b', 'a', 'd'}, false},
		{"wrong username", []byte{1, 3, 'b', 'a', 'd', 4, 'p', 'a', 's', 's'}, false},
		{"bad version", []byte{2, 4}, false},
		{"empty user", []byte{1, 0}, false},
		{"empty password", []byte{1, 4, 'u', 's', 'e', 'r', 0}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			a.SetDeadline(time.Now().Add(time.Second))
			b.SetDeadline(time.Now().Add(time.Second))
			done := make(chan error, 1)
			go func() { done <- HandshakeWithAuth(a, &Credentials{"user", "pass"}) }()
			b.Write([]byte{5, 2, 0, 2})
			reply := make([]byte, 2)
			if _, e := io.ReadFull(b, reply); e != nil || reply[1] != 2 {
				t.Fatalf("method %v %v", reply, e)
			}
			for _, v := range tc.payload {
				if _, e := b.Write([]byte{v}); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := io.ReadFull(b, reply); e != nil {
				t.Fatal(e)
			}
			if reply[0] != 1 || (reply[1] == 0) != tc.ok {
				t.Fatal(reply)
			}
			if err := <-done; (err == nil) != tc.ok {
				t.Fatalf("auth result %v", err)
			}
		})
	}
}
func TestAuthCannotDowngrade(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(time.Second))
	b.SetDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() { done <- HandshakeWithAuth(a, &Credentials{"user", "pass"}) }()
	b.Write([]byte{5, 1, 0})
	r := make([]byte, 2)
	io.ReadFull(b, r)
	if r[1] != 255 {
		t.Fatal(r)
	}
	if <-done == nil {
		t.Fatal("unauthenticated accepted")
	}
}
func TestAuthTruncated(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	a.SetDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() { done <- HandshakeWithAuth(a, &Credentials{"user", "pass"}) }()
	b.Write([]byte{5, 1, 2})
	io.ReadFull(b, make([]byte, 2))
	b.Write([]byte{1, 4, 'u'})
	b.Close()
	if <-done == nil {
		t.Fatal("truncated accepted")
	}
}
