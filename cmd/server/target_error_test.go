package main

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/tunnel"
)

func TestServerConnectFailureReturnsTypedError(t *testing.T) {
	reserved, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := reserved.Addr().String()
	reserved.Close()
	server, client := net.Pipe()
	defer client.Close()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		handleTunnel(server, &config.ServerConfig{AuthToken: "test-token"}, slog.New(slog.NewTextHandler(io.Discard, nil)), func() {})
	}()
	client.SetDeadline(time.Now().Add(time.Second))
	if err := tunnel.SendSetup(client, "test-token", target); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	if line, err := tunnel.ReadLine(reader); err != nil || line != "OK" {
		t.Fatal(line, err)
	}
	if line, err := tunnel.ReadLine(reader); err != nil || line != "ERR REFUSED" {
		t.Fatal(line, err)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("server failure cleanup leaked")
	}
}
