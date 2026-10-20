package socks5

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"mygotunnel/internal/authlimit"
)

type authReadSignal struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *authReadSignal) Read(b []byte) (int, error) {
	if len(b) == 2 {
		c.once.Do(func() { close(c.started) })
	}
	return c.Conn.Read(b)
}

func TestSlowSOCKSAuthenticationObservesNewBlock(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	if err := server.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	limiter := authlimit.New(8, 1, time.Minute, time.Minute)
	wrapped := &authReadSignal{Conn: server, started: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		_, err := HandshakeWithAuthPolicy(wrapped, &Credentials{Username: "u", Password: "p"}, limiter)
		done <- err
	}()
	if _, err := client.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil || reply != [2]byte{5, 2} {
		t.Fatalf("method=%v error=%v", reply, err)
	}
	select {
	case <-wrapped.started:
	case <-time.After(time.Second):
		t.Fatal("authentication read did not start")
	}
	peer := authlimit.PeerKey(server.RemoteAddr())
	if err := limiter.Authenticate(peer, false); !errors.Is(err, authlimit.ErrRejected) {
		t.Fatal(err)
	}
	if limiter.Allow(peer) {
		t.Fatal("expected newly blocked peer")
	}
	if _, err := client.Write([]byte{1, 1, 'u', 1, 'p'}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, reply[:]); err != nil || reply != [2]byte{1, 1} {
		t.Fatalf("auth=%v error=%v", reply, err)
	}
	if err := <-done; !errors.Is(err, ErrAuthLimited) {
		t.Fatalf("in-flight request bypassed block: %v", err)
	}
	if limiter.Allow(peer) {
		t.Fatal("in-flight request cleared the block")
	}
}

func TestMalformedAndTruncatedSOCKSAuthenticationDoNotCountPasswordFailures(t *testing.T) {
	for _, tc := range []struct {
		name       string
		payload    []byte
		closeEarly bool
		want       error
	}{
		{name: "version", payload: []byte{2, 1}, want: ErrAuthProtocol},
		{name: "empty username", payload: []byte{1, 0}, want: ErrAuthProtocol},
		{name: "empty password", payload: []byte{1, 1, 'u', 0}, want: ErrAuthProtocol},
		{name: "truncated", payload: []byte{1, 2, 'u'}, closeEarly: true, want: io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			server.SetDeadline(time.Now().Add(time.Second))
			client.SetDeadline(time.Now().Add(time.Second))
			limiter := authlimit.New(8, 1, time.Minute, time.Minute)
			done := make(chan error, 1)
			go func() {
				_, err := HandshakeWithAuthPolicy(server, &Credentials{Username: "u", Password: "p"}, limiter)
				done <- err
			}()
			if _, err := client.Write([]byte{5, 1, 2}); err != nil {
				t.Fatal(err)
			}
			var reply [2]byte
			if _, err := io.ReadFull(client, reply[:]); err != nil {
				t.Fatal(err)
			}
			if _, err := client.Write(tc.payload); err != nil {
				t.Fatal(err)
			}
			if tc.closeEarly {
				client.Close()
			} else if _, err := io.ReadFull(client, reply[:]); err != nil || reply != [2]byte{1, 1} {
				t.Fatalf("reply=%v error=%v", reply, err)
			}
			if err := <-done; !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want=%v", err, tc.want)
			}
			if err := limiter.Authenticate(authlimit.PeerKey(server.RemoteAddr()), true); err != nil {
				t.Fatalf("non-password failure blocked peer: %v", err)
			}
		})
	}
}

func TestSOCKSAuthenticationReadTimeoutDoesNotCountPasswordFailure(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	limiter := authlimit.New(8, 1, time.Minute, time.Minute)
	done := make(chan error, 1)
	go func() {
		_, err := HandshakeWithAuthPolicy(server, &Credentials{Username: "u", Password: "p"}, limiter)
		done <- err
	}()
	if _, err := client.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(client, method[:]); err != nil {
		t.Fatal(err)
	}
	if err := server.SetDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		var network net.Error
		if !errors.As(err, &network) || !network.Timeout() {
			t.Fatalf("expected read timeout, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("authentication read did not time out")
	}
	if err := limiter.Authenticate(authlimit.PeerKey(server.RemoteAddr()), true); err != nil {
		t.Fatalf("read timeout counted as password mismatch: %v", err)
	}
}
