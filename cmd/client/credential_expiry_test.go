package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"mygotunnel/internal/config"
)

type firstCredentialRead struct {
	net.Conn
	first chan struct{}
	once  sync.Once
}

func (c *firstCredentialRead) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.first) })
	return c.Conn.Read(p)
}

func TestOldSOCKSCredentialExpiresWhileWaitingForGreeting(t *testing.T) {
	expires := time.Now().Add(150 * time.Millisecond)
	cfg := &config.ClientConfig{
		SOCKSAuth:         &config.SOCKSAuth{Username: "u", Password: "new"},
		PreviousSOCKSAuth: []config.PreviousSOCKSAuth{{Username: "u", Password: "old", ExpiresAt: expires}},
	}
	server, client := net.Pipe()
	defer client.Close()
	tracked := &firstCredentialRead{Conn: server, first: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleClientContext(context.Background(), tracked, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), func() {})
	}()
	<-tracked.first // authentication began before the credential expires
	if time.Now().After(expires) {
		t.Fatal("test did not start before credential expiry")
	}
	time.Sleep(time.Until(expires) + 10*time.Millisecond)
	_ = client.SetDeadline(time.Now().Add(time.Second))
	if _, err := client.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	var response [2]byte
	if _, err := io.ReadFull(client, response[:]); err != nil || response != [2]byte{5, 2} {
		t.Fatal(response, err)
	}
	if _, err := client.Write([]byte{1, 1, 'u', 3, 'o', 'l', 'd'}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, response[:]); err != nil || response != [2]byte{1, 1} {
		t.Fatalf("expired credential accepted: %v %v", response, err)
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("rejected handshake did not finish")
	}
}
