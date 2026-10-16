package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/tunnel"
)

func TestOrdinaryRemoteErrorsReachSOCKSReply(t *testing.T) {
	certs := httptest.NewTLSServer(nil)
	cert := certs.TLS.Certificates[0]
	certs.Close()
	pin := sha256.Sum256(cert.Certificate[0])
	for _, tc := range []struct {
		reply string
		code  byte
	}{
		{"ERR", 5}, {"ERR TIMEOUT", 4}, {"ERR DNS", 4}, {"ERR NETWORK", 3}, {"ERR HOST", 4},
		{"ERR REFUSED", 5}, {"ERR LIMIT", 1}, {"ERR CANCELED", 1}, {"ERR INTERNAL", 1}, {"ERR UNKNOWN", 1},
	} {
		t.Run(tc.reply, func(t *testing.T) {
			listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			remoteDone := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					remoteDone <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				reader := bufio.NewReader(conn)
				for i := 0; i < 2; i++ {
					if _, err = tunnel.ReadLine(reader); err != nil {
						remoteDone <- err
						return
					}
				}
				_, err = io.WriteString(conn, "OK\n"+tc.reply+"\n")
				remoteDone <- err
			}()
			front, peer := net.Pipe()
			defer peer.Close()
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				handleClient(front, &config.ClientConfig{RemoteAddr: listener.Addr().String(), AuthToken: "test-token", CertificateFingerprint: hex.EncodeToString(pin[:])}, slog.New(slog.NewTextHandler(io.Discard, nil)), func() {})
			}()
			peer.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err = peer.Write([]byte{5, 1, 0}); err != nil {
				t.Fatal(err)
			}
			var method [2]byte
			if _, err = io.ReadFull(peer, method[:]); err != nil {
				t.Fatal(err)
			}
			if _, err = peer.Write([]byte{5, 1, 0, 1, 192, 0, 2, 1, 1, 187}); err != nil {
				t.Fatal(err)
			}
			var reply [10]byte
			if _, err = io.ReadFull(peer, reply[:]); err != nil || reply[0] != 5 || reply[1] != tc.code {
				t.Fatalf("reply %v: %v", reply, err)
			}
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("frontend handler leaked")
			}
			if err := <-remoteDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}
