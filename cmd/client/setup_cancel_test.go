package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/tunnel"
)

type setupIngressConn struct {
	net.Conn
	readEnd chan struct{}
	once    sync.Once
}

func (c *setupIngressConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		c.once.Do(func() { close(c.readEnd) })
	}
	return n, err
}

func (c *setupIngressConn) CloseWrite() error {
	return c.Conn.(interface{ CloseWrite() error }).CloseWrite()
}

type setupClientFixture struct {
	app      *net.TCPConn
	done     chan struct{}
	readEnd  chan struct{}
	released atomic.Bool
	logs     bytes.Buffer
}

func newSetupClientFixture(t *testing.T, remote func(net.Conn, *bufio.Reader)) *setupClientFixture {
	t.Helper()
	certSource := httptest.NewTLSServer(nil)
	cert := certSource.TLS.Certificates[0]
	certSource.Close()
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	local, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	app, err := net.Dial("tcp4", local.Addr().String())
	if err != nil {
		listener.Close()
		local.Close()
		t.Fatal(err)
	}
	front, err := local.Accept()
	local.Close()
	if err != nil {
		listener.Close()
		app.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &setupClientFixture{app: app.(*net.TCPConn), done: make(chan struct{}), readEnd: make(chan struct{})}
	pin := sha256.Sum256(cert.Certificate[0])
	cfg := &config.ClientConfig{RemoteAddr: listener.Addr().String(), AuthToken: "setup-watch-test", CertificateFingerprint: hex.EncodeToString(pin[:])}
	remoteReady, remoteDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(remoteDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { _ = conn.(*tls.Conn).NetConn().Close() })
		defer stop()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		reader := bufio.NewReader(conn)
		line, err := tunnel.ReadLine(reader)
		if err != nil || line != "AUTH "+cfg.AuthToken || tunnel.SendOK(conn) != nil {
			return
		}
		if _, err := tunnel.ReadLine(reader); err != nil {
			return
		}
		close(remoteReady)
		remote(conn, reader)
	}()
	go func() {
		defer close(f.done)
		defer f.released.Store(true) // same final release as admission.Permit
		handleClientContext(ctx, &setupIngressConn{Conn: front, readEnd: f.readEnd}, cfg,
			slog.New(slog.NewJSONHandler(&f.logs, nil)), func() { f.released.Store(true) })
	}()
	t.Cleanup(func() {
		cancel()
		app.Close()
		listener.Close()
		select {
		case <-f.done:
		case <-time.After(time.Second):
			t.Error("client setup handler leaked")
		}
		select {
		case <-remoteDone:
		case <-time.After(time.Second):
			t.Error("remote setup handler leaked")
		}
	})
	if err := app.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(app, method); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, 1, 187}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-remoteReady:
	case <-time.After(time.Second):
		t.Fatal("remote setup did not start")
	}
	return f
}

func TestHandleClientRSTCancelsRemoteSetup(t *testing.T) {
	for _, early := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "early_payload"}[early], func(t *testing.T) {
			remoteGone := make(chan struct{})
			f := newSetupClientFixture(t, func(conn net.Conn, reader *bufio.Reader) {
				defer close(remoteGone)
				_, _ = io.Copy(io.Discard, reader) // withhold CONNECT result
			})
			if early {
				if _, err := io.WriteString(f.app, "early request"); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.app.SetLinger(0); err != nil {
				t.Fatal(err)
			}
			if err := f.app.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-f.done:
			case <-time.After(time.Second):
				t.Fatal("RST did not release setup handler")
			}
			if !f.released.Load() || !strings.Contains(f.logs.String(), `"close_reason":"reset"`) {
				t.Fatalf("reset setup was not released/classified: released=%v logs=%s", f.released.Load(), f.logs.String())
			}
			select {
			case <-remoteGone:
			case <-time.After(time.Second):
				t.Fatal("RST did not close unused remote setup")
			}
		})
	}
}

func TestHandleClientFINBeforeRemoteResultPreservesPayload(t *testing.T) {
	allowResult := make(chan struct{})
	remoteResult := make(chan error, 1)
	const request = "request before SOCKS success\x00\n"
	const response = "reply after upload FIN\x00\n"
	f := newSetupClientFixture(t, func(conn net.Conn, reader *bufio.Reader) {
		select {
		case <-allowResult:
		case <-time.After(2 * time.Second):
			return
		}
		if err := tunnel.SendOK(conn); err != nil {
			remoteResult <- err
			return
		}
		got, err := io.ReadAll(reader)
		if err == nil && string(got) != request {
			err = errors.New("early request was lost")
		}
		if err == nil {
			_, err = io.WriteString(conn, response)
		}
		remoteResult <- err
	})
	if _, err := io.WriteString(f.app, request); err != nil {
		t.Fatal(err)
	}
	if err := f.app.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.readEnd: // ensure setup watcher actually saw FIN before success
	case <-time.After(time.Second):
		t.Fatal("setup watcher did not read FIN")
	}
	close(allowResult)
	reply := make([]byte, 10)
	if _, err := io.ReadFull(f.app, reply); err != nil || reply[1] != 0 {
		t.Fatalf("SOCKS reply %v, %v", reply, err)
	}
	got, err := io.ReadAll(f.app)
	if err != nil || string(got) != response {
		t.Fatalf("response = %q, %v", got, err)
	}
	if err := <-remoteResult; err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.done:
	case <-time.After(time.Second):
		t.Fatal("FIN relay did not drain")
	}
}
