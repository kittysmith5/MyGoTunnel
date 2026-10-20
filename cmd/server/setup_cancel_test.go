package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/tunnel"
)

type targetSetupIngressConn struct {
	net.Conn
	readEnd chan struct{}
	once    sync.Once
}

func (c *targetSetupIngressConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		c.once.Do(func() { close(c.readEnd) })
	}
	return n, err
}

func TestTargetDialIngressResetCancelsButFINDoesNot(t *testing.T) {
	for _, reset := range []bool{true, false} {
		for _, early := range []bool{false, true} {
			name := map[bool]string{true: "RST", false: "FIN"}[reset] + map[bool]string{false: "_empty", true: "_early_payload"}[early]
			t.Run(name, func(t *testing.T) {
				resolving := make(chan struct{})
				var resolvingOnce sync.Once
				previous := net.DefaultResolver
				net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
					resolvingOnce.Do(func() { close(resolving) })
					<-ctx.Done()
					return nil, ctx.Err()
				}}
				defer func() { net.DefaultResolver = previous }()
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				client, err := net.Dial("tcp4", listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				server, err := listener.Accept()
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				readEnd, done := make(chan struct{}), make(chan struct{})
				var logs bytes.Buffer
				go func() {
					defer close(done)
					handleTunnelContext(ctx, &targetSetupIngressConn{Conn: server, readEnd: readEnd}, &config.ServerConfig{AuthToken: "target-setup-test"}, slog.New(slog.NewJSONHandler(&logs, nil)), func() {}, nil)
				}()
				t.Cleanup(func() {
					cancel()
					client.Close()
					select {
					case <-done:
					case <-time.After(time.Second):
						t.Error("target setup handler leaked")
					}
				})
				if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				if err := tunnel.SendAuth(client, "target-setup-test"); err != nil {
					t.Fatal(err)
				}
				reader := bufio.NewReader(client)
				if line, err := tunnel.ReadLine(reader); err != nil || line != "OK" {
					t.Fatalf("AUTH = %q, %v", line, err)
				}
				payload := ""
				if early {
					payload = "early target request\x00\n"
				}
				if _, err := io.WriteString(client, "CONNECT pending.setup.test:443\n"+payload); err != nil {
					t.Fatal(err)
				}
				select {
				case <-resolving:
				case <-time.After(time.Second):
					t.Fatal("target DNS did not start")
				}
				if reset {
					if err := client.(*net.TCPConn).SetLinger(0); err != nil {
						t.Fatal(err)
					}
					if err := client.Close(); err != nil {
						t.Fatal(err)
					}
					select {
					case <-done:
					case <-time.After(time.Second):
						t.Fatal("RST did not cancel target dial")
					}
					if !strings.Contains(logs.String(), `"close_reason":"reset"`) {
						t.Fatalf("reset root cause was lost: %s", logs.String())
					}
					return
				}
				if err := client.(*net.TCPConn).CloseWrite(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-readEnd:
				case <-time.After(time.Second):
					t.Fatal("watcher did not observe FIN")
				}
				select {
				case <-done:
					t.Fatal("FIN incorrectly canceled target setup")
				case <-time.After(50 * time.Millisecond):
				}
				cancel() // deliberately end the held lookup after verifying FIN
				line, err := tunnel.ReadLine(reader)
				if err != nil || (line != "ERR CANCELED" && line != "ERR DNS") {
					t.Fatalf("half-closed ingress lost reverse reply: %q, %v", line, err)
				}
			})
		}
	}
}
