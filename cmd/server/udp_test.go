package main

import (
	"bufio"
	"bytes"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
)

type udpReadErrorSignal struct {
	failed chan struct{}
	once   sync.Once
}

func (s *udpReadErrorSignal) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("read target UDP failed")) {
		s.once.Do(func() { close(s.failed) })
	}
	return len(p), nil
}

func TestUDPTunnelRecoversAfterTargetReadError(t *testing.T) {
	reserved, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	address := reserved.LocalAddr().(*net.UDPAddr)
	_ = reserved.Close()
	signal := &udpReadErrorSignal{failed: make(chan struct{})}
	logger := slog.New(slog.NewTextHandler(signal, &slog.HandlerOptions{Level: slog.LevelDebug}))
	server, client := net.Pipe()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan struct{})
	go func() {
		handleTunnel(server, &config.ServerConfig{AuthToken: "test-token"}, logger)
		close(done)
	}()
	defer func() {
		_ = client.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("target recovery session did not clean up its workers")
		}
	}()
	reader := bufio.NewReader(client)
	for _, command := range []string{"AUTH test-token\n", "UDP\n"} {
		if _, err := io.WriteString(client, command); err != nil {
			t.Fatal(err)
		}
		if response, err := tunnel.ReadLine(reader); err != nil || response != "OK" {
			t.Fatalf("handshake: %q, %v", response, err)
		}
	}
	packet := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "127.0.0.1", Port: uint16(address.Port)}, []byte("recover"))
	if err := tunnel.WriteDatagram(client, packet); err != nil {
		t.Fatal(err)
	}
	select {
	case <-signal.failed:
	case <-time.After(time.Second):
		t.Fatal("target read did not report the closed-port error")
	}
	echo, err := net.ListenUDP("udp4", address)
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		data := make([]byte, 100)
		n, peer, err := echo.ReadFromUDP(data)
		if err == nil {
			_, _ = echo.WriteToUDP(data[:n], peer)
		}
	}()
	if err := tunnel.WriteDatagram(client, packet); err != nil {
		t.Fatal(err)
	}
	response, err := tunnel.ReadDatagram(reader)
	if err != nil || !bytes.Equal(response, packet) {
		t.Fatalf("recovered target did not return UDP response: %v", err)
	}
}

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
