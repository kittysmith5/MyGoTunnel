package quicstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/quicudp"
)

func fixture(t *testing.T) (*Listener, *Pool, *datagram.Resources, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.json")
	code, e := config.InitializeServer(path, "localhost:8443", "127.0.0.1:8443")
	if e != nil {
		t.Fatal(e)
	}
	cc, e := config.DecodeConnection(code)
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := config.LoadServerConfig(path)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if e != nil {
		t.Fatal(e)
	}
	resources := datagram.NewResources(8, 8<<20)
	ln, e := Listen("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{ALPN}, MinVersion: tls.VersionTLS13}, resources, 8, 8)
	if e != nil {
		t.Fatal(e)
	}
	tc, e := quicudp.ClientTLSConfig(ln.Addr().String(), "localhost", cc.CertificateFingerprint)
	if e != nil {
		t.Fatal(e)
	}
	pool := NewPool(ln.Addr().String(), tc, resources)
	t.Cleanup(func() {
		pool.Close()
		ln.Shutdown(0)
		if resources.Stats().Sockets != 0 {
			t.Error("socket leak", resources.Stats())
		}
		resources.Close()
	})
	return ln, pool, resources, cc.CertificateFingerprint
}
func TestStreamsMultiplexHalfCloseAndCancellation(t *testing.T) {
	ln, pool, _, _ := fixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var workers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			c.(*Stream).MarkAuthenticated()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				c.SetDeadline(time.Now().Add(4 * time.Second))
				body, e := io.ReadAll(c)
				if e == nil {
					_, _ = c.Write(append([]byte("after-fin:"), body...))
					c.(*Stream).CloseWrite()
				}
			}()
		}
	}()
	first, _, e := pool.Open(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	spare, _, e := pool.Open(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer spare.Close()
	second, _, e := pool.Open(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	if first.(*Stream).q != second.(*Stream).q {
		t.Fatal("cancellation test did not share a physical connection")
	}
	// A canceled/blocked read must not close the shared physical connection.
	first.SetReadDeadline(time.Now().Add(time.Millisecond))
	var x [1]byte
	if _, e = first.Read(x[:]); e == nil {
		t.Fatal("deadline ignored")
	}
	first.Close()
	payload := bytes.Repeat([]byte("late-response"), 1<<14)
	second.SetDeadline(time.Now().Add(3 * time.Second))
	sent := make(chan error, 1)
	go func() {
		_, e := second.Write(payload)
		if e == nil {
			e = second.(*Stream).CloseWrite()
		}
		sent <- e
	}()
	got, e := io.ReadAll(second)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(got, append([]byte("after-fin:"), payload...)) {
		t.Fatal("half-close truncated data")
	}
	if e = <-sent; e != nil {
		t.Fatal(e)
	}
	second.Close()
	reused, timing, e := pool.Open(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if !timing.Reused {
		t.Fatal("connection was not reused")
	}
	reused.Close()
	ln.Close()
	<-acceptDone
	workers.Wait()
}
func TestStreamPoolTrustBudgetAndDrain(t *testing.T) {
	ln, pool, r, _ := fixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	tc, _ := quicudp.ClientTLSConfig(ln.Addr().String(), "localhost", strings.Repeat("00", 32))
	bad := NewPool(ln.Addr().String(), tc, r)
	if c, _, e := bad.Open(ctx); e == nil {
		c.Close()
		t.Fatal("wrong pin accepted")
	}
	bad.Close()
	pool.Drain()
	if c, _, e := pool.Open(ctx); e == nil {
		c.Close()
		t.Fatal("draining pool accepted a stream")
	}
}
func TestListenerClosePreservesHandedOffStream(t *testing.T) {
	ln, pool, _, _ := fixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, _, e := pool.Open(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	if _, e = c.Write([]byte("x")); e != nil {
		t.Fatal(e)
	}
	server, e := ln.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	server.(*Stream).MarkAuthenticated()
	ln.Close()
	var one [1]byte
	if _, e = io.ReadFull(server, one[:]); e != nil {
		t.Fatal(e)
	}
	server.Write([]byte("y"))
	if _, e = io.ReadFull(c, one[:]); e != nil || one[0] != 'y' {
		t.Fatal(e)
	}
}

var _ net.Conn = (*Stream)(nil)

func TestOneSocketBudgetStillMultiplexesLiveConnection(t *testing.T) {
	ln, original, _, _ := fixture(t)
	r := datagram.NewResources(1, 262144)
	defer r.Close()
	pool := NewPool(ln.Addr().String(), original.tls, r)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	first, _, e := pool.Open(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	second, timing, e := pool.Open(ctx)
	if e != nil {
		t.Fatal("live connection ignored", e)
	}
	defer second.Close()
	n, active := pool.Stats()
	if n != 1 || active != 2 || !timing.Reused {
		t.Fatal(n, active, timing)
	}
}

func TestStreamCapacityFailsBoundedly(t *testing.T) {
	ln, original, _, _ := fixture(t)
	r := datagram.NewResources(1, 262144)
	defer r.Close()
	pool := NewPool(ln.Addr().String(), original.tls, r)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var streams []net.Conn
	defer func() {
		for _, c := range streams {
			c.Close()
		}
	}()
	for i := 0; i < streamLimit; i++ {
		c, _, e := pool.Open(ctx)
		if e != nil {
			t.Fatal(i, e)
		}
		streams = append(streams, c)
	}
	c, _, e := pool.Open(ctx)
	if c != nil || e != ErrBusy {
		t.Fatal("stream capacity not bounded", e)
	}
}
