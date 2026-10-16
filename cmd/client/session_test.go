package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"mygotunnel/internal/config"
	"mygotunnel/internal/preconnect"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestPreparedTransportFallbackAndExplicitRejection(t *testing.T) {
	for _, command := range []string{"tcp", "udp"} {
		for _, mode := range []string{"transport failure", "explicit rejection"} {
			t.Run(command+"/"+mode, func(t *testing.T) {
				wantCommand := "CONNECT target.test:443\n"
				if command == "udp" {
					wantCommand = "UDP\n"
				}
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
				certificate, err := tls.LoadX509KeyPair(server.CertFile, server.KeyFile)
				if err != nil {
					t.Fatal(err)
				}
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				cfg.RemoteAddr = listener.Addr().String()
				serverDone := make(chan error, 1)
				if mode == "transport failure" {
					go func() {
						raw, err := listener.Accept()
						if err != nil {
							serverDone <- err
							return
						}
						defer raw.Close()
						conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}})
						conn.SetDeadline(time.Now().Add(3 * time.Second))
						reader := bufio.NewReader(conn)
						auth, err := reader.ReadString('\n')
						if err == nil && auth != "AUTH "+cfg.AuthToken+"\n" {
							err = io.ErrUnexpectedEOF
						}
						if err == nil {
							var line string
							line, err = reader.ReadString('\n')
							if err == nil && line != wantCommand {
								err = io.ErrUnexpectedEOF
							}
						}
						if err == nil {
							_, err = io.WriteString(conn, "OK\nOK\nprefetched payload\x00\n")
						}
						serverDone <- err
					}()
				}
				var calls atomic.Int32
				peerDone := make(chan error, 1)
				pool, err := preconnect.New(preconnect.Options{Size: 1}, func(ctx context.Context) (*preconnect.Entry, error) {
					if calls.Add(1) > 1 {
						<-ctx.Done()
						return nil, ctx.Err()
					}
					a, b := net.Pipe()
					go func() {
						defer b.Close()
						b.SetDeadline(time.Now().Add(3 * time.Second))
						line, err := bufio.NewReader(b).ReadString('\n')
						if err == nil && line != wantCommand {
							err = io.ErrUnexpectedEOF
						}
						if err == nil && mode == "explicit rejection" {
							_, err = io.WriteString(b, "ERR\n")
						}
						peerDone <- err
					}()
					return &preconnect.Entry{Conn: a, Reader: bufio.NewReader(a)}, nil
				}, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer pool.Close()
				deadline := time.Now().Add(time.Second)
				for pool.IdleCount() == 0 && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if pool.IdleCount() != 1 {
					t.Fatal("pool did not become ready")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				var session *remoteSession
				if command == "udp" {
					session, err = openRemoteUDP(ctx, cfg, pool)
				} else {
					session, err = openRemote(ctx, cfg, "target.test:443", pool)
				}
				stats := pool.Stats()
				wantFallback := uint64(0)
				if mode == "transport failure" {
					wantFallback = 1
				}
				if stats.Hits != 1 || stats.Misses != 0 || stats.Fallbacks != wantFallback {
					t.Fatalf("pool counters: %+v", stats)
				}

				if mode == "explicit rejection" {
					if !errors.Is(err, errTargetRejected) || session.PoolFallback {
						t.Fatal("explicit rejection was retried")
					}
				} else {
					if err != nil || !session.PoolFallback || session.PoolHit {
						t.Fatalf("transport fallback = %v", err)
					}
					data, err := io.ReadAll(session.Reader)
					session.Conn.Close()
					if err != nil || string(data) != "prefetched payload\x00\n" {
						t.Fatal("fallback lost buffered payload")
					}
					if err := <-serverDone; err != nil {
						t.Fatal(err)
					}
				}
				if err := <-peerDone; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
