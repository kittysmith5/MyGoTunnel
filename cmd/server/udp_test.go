package main

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
)

func TestUDPResponsesDropWhenQueueFull(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sender, err := net.DialUDP("udp4", nil, conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	queue := make(chan []byte, 1)
	queue <- []byte("already queued")
	stop, finished := make(chan struct{}), make(chan struct{})
	var received, dropped atomic.Uint64
	target := &udpTarget{conn: conn, destination: socks5.UDPDatagram{Host: "127.0.0.1", Port: 53}}
	go func() {
		readUDPResponses(target, queue, stop, &received, &dropped, slog.New(slog.NewTextHandler(io.Discard, nil)))
		close(finished)
	}()
	defer func() {
		close(stop)
		_ = conn.Close()
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			t.Error("response worker did not stop")
		}
	}()
	if _, err := sender.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for dropped.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if dropped.Load() != 1 || received.Load() != 0 || len(queue) != 1 || target.lastActivity.Load() == 0 {
		t.Fatalf("received=%d dropped=%d queued=%d", received.Load(), dropped.Load(), len(queue))
	}
}

func TestUDPTunnelRelaysDatagram(t *testing.T) {
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, peer, err := echo.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(buffer[:n], peer)
		}
	}()

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	done := make(chan struct{})
	go func() {
		handleTunnel(serverConn, &config.ServerConfig{AuthToken: "test-token"}, logger)
		close(done)
	}()
	reader := bufio.NewReader(clientConn)
	if err := tunnel.SendAuth(clientConn, "test-token"); err != nil {
		t.Fatal(err)
	}
	if line, err := tunnel.ReadLine(reader); err != nil || line != "OK" {
		t.Fatalf("auth response = %q, %v", line, err)
	}
	if err := tunnel.SendUDPAssociate(clientConn); err != nil {
		t.Fatal(err)
	}
	if line, err := tunnel.ReadLine(reader); err != nil || line != "OK" {
		t.Fatalf("UDP response = %q, %v", line, err)
	}

	addr := echo.LocalAddr().(*net.UDPAddr)
	request := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: addr.IP.String(), Port: uint16(addr.Port)}, []byte("echo-me"))
	if err := tunnel.WriteDatagram(clientConn, request); err != nil {
		t.Fatal(err)
	}
	_ = clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	response, err := tunnel.ReadDatagram(reader)
	if err != nil {
		t.Fatalf("read relayed response: %v", err)
	}
	destination, payload, err := socks5.ParseUDPDatagram(response)
	if err != nil {
		t.Fatal(err)
	}
	if destination.Port != uint16(addr.Port) || !net.ParseIP(destination.Host).Equal(addr.IP) || string(payload) != "echo-me" {
		t.Fatalf("unexpected UDP response: destination=%#v payload=%q", destination, payload)
	}

	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("UDP tunnel handler did not stop after control connection closed")
	}
}
