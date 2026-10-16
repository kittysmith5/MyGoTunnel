package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/logging"
	"mygotunnel/internal/tunnel"
)

func TestUDPTLSBlockedWriteStopsAllWorkersAndKeepsRootCause(t *testing.T) {
	certs := httptest.NewTLSServer(nil)
	cert := certs.TLS.Certificates[0]
	certs.Close()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	server := tls.Server(a, &tls.Config{Certificates: []tls.Certificate{cert}, SessionTicketsDisabled: true})
	client := tls.Client(b, &tls.Config{InsecureSkipVerify: true}) // generated test certificate only
	server.SetDeadline(time.Now().Add(time.Second))
	client.SetDeadline(time.Now().Add(time.Second))
	handshake := make(chan error, 1)
	go func() { handshake <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-handshake; err != nil {
		t.Fatal(err)
	}
	client.SetDeadline(time.Now().Add(time.Second))
	resources := datagram.NewResources(4, 1<<20)
	defer resources.Close()
	var logs bytes.Buffer
	logger, _ := loggingForUDPLimits(&logs)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		handleUDPTunnel(server, bufio.NewReader(server), logger, time.Now(), 0, func() {}, config.UDPQueueConfig{UDPWriteTimeoutMS: 30}, resources)
	}()
	reader := bufio.NewReader(client)
	if line, err := tunnel.ReadLine(reader); err != nil || line != "OK" {
		t.Fatal(line, err)
	}
	_, fast := udpIsolationEcho(t)
	if err := tunnel.WriteDatagram(client, fast); err != nil {
		t.Fatal(err)
	}
	// The peer deliberately never reads the response. net.Pipe gives TLS a
	// zero-capacity transport, so the response write deterministically stalls.
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("TLS timeout leaked UDP workers")
	}
	if s := resources.Stats(); s.Sockets != 0 || s.BufferBytes != s.CachedBytes || s.SessionErrors != 1 || s.WriteTimeouts != 1 || s.WriteErrors != 1 {
		t.Fatal(s)
	}
	if text := logs.String(); !strings.Contains(text, "stage=udp_tunnel_write reason=timeout") || !strings.Contains(text, "udp_tunnel_write_timeouts=1") {
		t.Fatal(text)
	}
}

func loggingForUDPLimits(w io.Writer) (*slog.Logger, error) {
	return logging.New(w, logging.Options{Component: "server", Level: "info", Format: "text"})
}

func TestUDPProcessSocketBudgetSharedAcrossAssociations(t *testing.T) {
	resources := datagram.NewResources(1, 1<<20)
	defer resources.Close()
	type session struct {
		conn   net.Conn
		reader *bufio.Reader
		done   chan struct{}
	}
	start := func() session {
		a, b := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			handleUDPTunnel(a, bufio.NewReader(a), slog.New(slog.NewTextHandler(io.Discard, nil)), time.Now(), 0, func() {}, config.UDPQueueConfig{}, resources)
		}()
		s := session{b, bufio.NewReader(b), done}
		t.Cleanup(func() {
			b.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("association workers leaked")
			}
		})
		b.SetDeadline(time.Now().Add(time.Second))
		if line, err := tunnel.ReadLine(s.reader); err != nil || line != "OK" {
			t.Fatal(line, err)
		}
		return s
	}
	first, second := start(), start()
	_, one := udpIsolationEcho(t)
	_, two := udpIsolationEcho(t)
	tunnel.WriteDatagram(first.conn, one)
	if got, err := tunnel.ReadDatagram(first.reader); err != nil || !bytes.Equal(got, one) {
		t.Fatal("initial target", err)
	}
	tunnel.WriteDatagram(second.conn, two)
	second.conn.SetReadDeadline(time.Now().Add(60 * time.Millisecond))
	if _, err := tunnel.ReadDatagram(second.reader); err == nil {
		t.Fatal("second association bypassed process socket cap")
	}
	first.conn.Close()
	select {
	case <-first.done:
	case <-time.After(time.Second):
		t.Fatal("socket reservation not released")
	}
	second.conn.SetDeadline(time.Now().Add(time.Second))
	tunnel.WriteDatagram(second.conn, two)
	if got, err := tunnel.ReadDatagram(second.reader); err != nil || !bytes.Equal(got, two) {
		t.Fatal("socket budget did not recover", err)
	}
	second.conn.Close()
	<-second.done
	if s := resources.Stats(); s.Sockets != 0 || s.BufferBytes != s.CachedBytes || s.SocketRejected == 0 {
		t.Fatal(s)
	}
}
