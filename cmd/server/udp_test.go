package main

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
)

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
