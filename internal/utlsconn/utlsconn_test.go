package utlsconn

import (
	"context"
	"crypto/tls"
	"io"
	"mygotunnel/internal/config"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCertificateVerification(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")
	code, err := config.InitializeServer(path, "localhost:9001", ":9001")
	if err != nil {
		t.Fatal(err)
	}
	client, err := config.DecodeConnection(code)
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
	for _, tc := range []struct {
		name, pin string
		success   bool
	}{
		{"matching pin", client.CertificateFingerprint, true},
		{"wrong pin", strings.Repeat("00", 32), false},
		{"no pin rejects self signed", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				raw, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(3 * time.Second))
				conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
				err = conn.Handshake()
				if err == nil && tc.success {
					state := conn.ConnectionState()
					if state.ServerName != "localhost" || state.NegotiatedProtocol != "http/1.1" {
						t.Error("SNI/ALPN mismatch")
					}
					_, err = io.WriteString(conn, "ok")
				}
				done <- err
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, err := Dial(ctx, listener.Addr().String(), "localhost", tc.pin)
			if tc.success {
				if err != nil {
					t.Fatal(err)
				}
				data := make([]byte, 2)
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				_, err = io.ReadFull(conn, data)
				conn.Close()
				if err != nil || string(data) != "ok" {
					t.Fatalf("payload: %v", err)
				}
			} else {
				if err == nil {
					conn.Close()
					t.Fatal("untrusted certificate accepted")
				}
			}
			if err := <-done; tc.success && err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, err := Dial(context.Background(), "127.0.0.1:1", "localhost", "bad"); err == nil {
		t.Fatal("invalid pin accepted")
	}
}
