package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"mygotunnel/internal/config"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type shortDeadlineConn struct{ net.Conn }

func (c shortDeadlineConn) SetDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		deadline = time.Now().Add(100 * time.Millisecond)
	}
	return c.Conn.SetDeadline(deadline)
}

func TestHandleClientTimesOutIncompleteSOCKS5(t *testing.T) {
	for _, request := range [][]byte{nil, {5, 1, 0}} {
		a, b := net.Pipe()
		defer b.Close()
		done := make(chan struct{})
		go func() {
			handleClient(shortDeadlineConn{a}, &config.ClientConfig{}, slog.New(slog.NewTextHandler(io.Discard, nil)), func() {})
			close(done)
		}()
		if len(request) != 0 {
			b.SetDeadline(time.Now().Add(time.Second))
			if _, err := b.Write(request); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, 2)
			if _, err := io.ReadFull(b, response); err != nil {
				t.Fatal(err)
			}
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			b.Close()
			t.Fatal("incomplete SOCKS5 connection did not time out")
		}
	}
}

func TestHandleClientRejectsUnsupportedCommand(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	b.SetDeadline(time.Now().Add(time.Second))
	done := make(chan struct{})
	go func() {
		handleClient(a, &config.ClientConfig{}, slog.New(slog.NewTextHandler(io.Discard, nil)), func() {})
		close(done)
	}()
	if _, err := b.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(b, response); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte{5, 2, 0, 1}); err != nil {
		t.Fatal(err)
	}
	response = make([]byte, 10)
	if _, err := io.ReadFull(b, response); err != nil {
		t.Fatal(err)
	}
	if response[1] != 7 {
		t.Fatalf("reply = %d, want 7", response[1])
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("client did not return")
	}
}

func TestHandleClientPipelinesBeforeResponsesAndPreservesPayload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")
	code, err := config.InitializeServer(path, "localhost:9001", ":9001")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.DecodeConnection(code)
	if err != nil {
		t.Fatal(err)
	}
	server, err := config.LoadServerConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(server.CertFile, server.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	cfg.RemoteAddr = remote.Addr().String()
	remoteDone := make(chan error, 1)
	const request = "binary request\x00\n"
	const prefix = "prefetched response\x00\n"
	const suffix = "response after EOF\x00\n"
	go func() {
		raw, err := remote.Accept()
		if err != nil {
			remoteDone <- err
			return
		}
		defer raw.Close()
		conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		reader := bufio.NewReader(conn)
		// Both lines must arrive before sending the first response.
		auth, err := reader.ReadString('\n')
		if err == nil && auth != "AUTH "+cfg.AuthToken+"\n" {
			err = fmt.Errorf("unexpected AUTH")
		}
		if err == nil {
			var line string
			line, err = reader.ReadString('\n')
			if err == nil && line != "CONNECT example.test:443\n" {
				err = fmt.Errorf("unexpected CONNECT")
			}
		}
		if err == nil {
			_, err = io.WriteString(conn, "OK\nOK\n"+prefix)
		}
		if err == nil {
			var payload []byte
			payload, err = io.ReadAll(reader)
			if err == nil && string(payload) != request {
				err = fmt.Errorf("payload mismatch")
			}
		}
		if err == nil {
			_, err = io.WriteString(conn, suffix)
		}
		remoteDone <- err
	}()
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	var released atomic.Bool
	clientDone := make(chan struct{})
	go func() {
		conn, err := local.Accept()
		if err != nil {
			close(clientDone)
			return
		}
		handleClient(conn, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), func() { released.Store(true) })
		close(clientDone)
	}()
	app, err := net.Dial("tcp", local.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	app.SetDeadline(time.Now().Add(3 * time.Second))
	app.Write([]byte{5, 1, 0})
	response := make([]byte, 2)
	if _, err := io.ReadFull(app, response); err != nil {
		t.Fatal(err)
	}
	host := "example.test"
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, []byte(host)...)
	req = append(req, 1, 187)
	app.Write(req)
	response = make([]byte, 10)
	if _, err := io.ReadFull(app, response); err != nil || response[1] != 0 {
		t.Fatalf("SOCKS response: %v", err)
	}
	io.WriteString(app, request)
	app.(*net.TCPConn).CloseWrite()
	payload, err := io.ReadAll(app)
	if err != nil || string(payload) != prefix+suffix {
		t.Fatalf("response payload = %q, %v", payload, err)
	}
	if !released.Load() {
		t.Fatal("setup permit was not released before relay completed")
	}
	if err := <-remoteDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-clientDone:
	case <-time.After(3 * time.Second):
		t.Fatal("client did not finish")
	}
}

func TestRunRejectsInvalidSetupLimit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := run("unused", logger, 0); err == nil || !strings.Contains(err.Error(), "max-setup") {
		t.Fatal("invalid max-setup accepted")
	}
}

func TestRunRejectsInvalidQUICPoolSize(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, size := range []int{-1, 33} {
		if err := run("unused", logger, 1, clientOptions{maxConnections: 1, quicPoolSize: size}); err == nil || !strings.Contains(err.Error(), "quic-pool-size") {
			t.Fatalf("invalid QUIC pool size %d accepted: %v", size, err)
		}
	}
}
