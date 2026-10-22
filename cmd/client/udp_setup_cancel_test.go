package main

import (
	"bufio"
	"context"
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
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
)

func udpSetupControlPair(t *testing.T) (*net.TCPConn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	peer, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := ln.Accept()
	if err != nil {
		peer.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close(); conn.Close() })
	return peer.(*net.TCPConn), conn
}

// Disconnect during every blocking setup phase. A FIN also ends a UDP
// association, unlike the upload half-close of a TCP CONNECT request.
func TestUDPSetupControlDisconnectCancelsEveryStage(t *testing.T) {
	for _, stage := range []string{"source_dns", "tls", "auth", "udp_reply"} {
		for _, disconnect := range []string{"close", "fin", "rst"} {
			t.Run(stage+"/"+disconnect, func(t *testing.T) {
				resources := datagram.NewResources(4, 1<<20)
				defer resources.Close()
				peer, conn := udpSetupControlPair(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				reached := make(chan struct{})
				cfg := &config.ClientConfig{AuthToken: "test-token"}
				request := socks5.Request{Command: 3, Address: "0.0.0.0"}
				lookup := net.DefaultResolver.LookupIPAddr
				if stage == "source_dns" {
					request.Address = "source.invalid"
					lookup = func(ctx context.Context, _ string) ([]net.IPAddr, error) {
						close(reached)
						<-ctx.Done()
						return nil, ctx.Err()
					}
				} else {
					ln, err := net.Listen("tcp4", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer ln.Close()
					cfg.RemoteAddr = ln.Addr().String()
					var tlsConfig *tls.Config
					if stage != "tls" {
						certSource := httptest.NewTLSServer(nil)
						cert := certSource.TLS.Certificates[0]
						certSource.Close()
						tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}}
						pin := sha256.Sum256(cert.Certificate[0])
						cfg.CertificateFingerprint = hex.EncodeToString(pin[:])
					}
					remoteDone := make(chan struct{})
					go func() {
						defer close(remoteDone)
						remote, err := ln.Accept()
						if err != nil {
							return
						}
						defer remote.Close()
						_ = remote.SetDeadline(time.Now().Add(3 * time.Second))
						if tlsConfig == nil {
							close(reached)
							_, _ = io.Copy(io.Discard, remote)
							return
						}
						tlsRemote := tls.Server(remote, tlsConfig)
						reader := bufio.NewReader(tlsRemote)
						if line, err := tunnel.ReadLine(reader); err != nil || line != "AUTH test-token" {
							return
						}
						if stage == "udp_reply" {
							if err := tunnel.SendOK(tlsRemote); err != nil {
								return
							}
							if line, err := tunnel.ReadLine(reader); err != nil || line != "UDP" {
								return
							}
						}
						close(reached)
						_, _ = io.Copy(io.Discard, reader)
					}()
					defer func() {
						ln.Close()
						select {
						case <-remoteDone:
						case <-time.After(4 * time.Second):
							t.Error("remote setup stub leaked")
						}
					}()
				}
				done := make(chan struct{})
				go func() {
					defer close(done)
					handleUDPAssociateWithResolver(ctx, conn, request, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Now(), func() {}, nil, lookup, resources)
				}()
				defer func() {
					cancel()
					conn.Close()
					select {
					case <-done:
					case <-time.After(time.Second):
						t.Error("setup worker leaked")
					}
				}()
				select {
				case <-reached:
				case <-time.After(time.Second):
					t.Fatal("setup did not reach " + stage)
				}
				started := time.Now()
				if disconnect == "fin" {
					if err := peer.CloseWrite(); err != nil {
						t.Fatal(err)
					}
				} else {
					if disconnect == "rst" {
						if err := peer.SetLinger(0); err != nil {
							t.Fatal(err)
						}
					}
					_ = peer.Close()
				}
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("disconnected control connection retained setup")
				}
				if s := resources.Stats(); s.Sockets != 0 || s.ResidentBytes != 0 || s.BufferBytes != s.CachedBytes {
					t.Fatalf("setup retained resources: %+v", s)
				}
				t.Logf("setup cancellation: %s", time.Since(started))
			})
		}
	}
}

func TestUDPAssociationControlFINStopsEstablishedSession(t *testing.T) {
	resources := datagram.NewResources(4, 1<<20)
	defer resources.Close()
	session := newUDPAssociationTest(t, socks5.Request{Command: 3, Address: "0.0.0.0"}, resources)
	if err := session.control.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.done:
	case <-time.After(time.Second):
		t.Fatal("UDP control FIN did not stop established session")
	}
	if s := resources.Stats(); s.Sockets != 0 || s.ResidentBytes != 0 {
		t.Fatalf("association retained resources: %+v", s)
	}
}
