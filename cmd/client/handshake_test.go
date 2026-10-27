package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"mygotunnel/internal/config"
	"mygotunnel/internal/handshake"
	"mygotunnel/internal/ingress"
	"mygotunnel/internal/preconnect"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type handshakeFixture struct {
	cfg      *config.ClientConfig
	rejected atomic.Int32
	auth     chan struct{}
	barrier  chan struct{}
}

func newHandshakeFixture(t *testing.T, block bool) *handshakeFixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.json")
	code, e := config.InitializeServer(path, "localhost:9001", ":9001")
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := config.DecodeConnection(code)
	if e != nil {
		t.Fatal(e)
	}
	sc, e := config.LoadServerConfig(path)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := tls.LoadX509KeyPair(sc.CertFile, sc.KeyFile)
	if e != nil {
		t.Fatal(e)
	}
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	cfg.RemoteAddr = ln.Addr().String()
	f := &handshakeFixture{cfg: cfg, auth: make(chan struct{}, 64)}
	if block {
		f.barrier = make(chan struct{})
	}
	guard := ingress.NewGuard(8, 20, 8)
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			raw, e := ln.Accept()
			if e != nil {
				return
			}
			release, ok := guard.Acquire(raw.RemoteAddr())
			if !ok {
				f.rejected.Add(1)
				raw.Close()
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer raw.Close()
				defer release()
				_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
				c := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
				r := bufio.NewReader(c)
				auth, e := r.ReadString('\n')
				if e != nil || auth != "AUTH "+cfg.AuthToken+"\n" {
					return
				}
				if _, e = io.WriteString(c, "OK\n"); e != nil {
					return
				}
				release()
				f.auth <- struct{}{}
				command, e := r.ReadString('\n')
				if e != nil {
					return
				}
				if f.barrier != nil {
					<-f.barrier
				}
				if command == "PREPARE ACK\n" {
					if _, e = io.WriteString(c, "READY ACK\n"); e == nil {
						_, _ = r.ReadByte()
					}
					return
				}
				if !strings.HasPrefix(command, "CONNECT ") {
					return
				}
				_, _ = io.WriteString(c, "OK\npayload")
			}()
		}
	}()
	t.Cleanup(func() { ln.Close(); <-done; wg.Wait() })
	return f
}
func TestSharedHandshakeBudgetAcrossForegroundAndPreparer(t *testing.T) {
	f := newHandshakeFixture(t, false)
	s := handshake.New(handshake.Options{Rate: 16, Burst: 4, Concurrent: 4, Background: 1, Queue: 64, MaxWait: 5 * time.Second})
	ctx, cancel := context.WithTimeout(handshake.WithScheduler(context.Background(), s), 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 22)
	for i := range 22 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i < 2 {
				entry, e := preconnect.NewPreparer(f.cfg, s)(ctx)
				if e == nil {
					closeUnusedRemote(entry.Conn)
				}
				errs <- e
				return
			}
			session, e := openRemote(ctx, f.cfg, "target.invalid:443", nil)
			if e == nil {
				data := make([]byte, 7)
				_, e = io.ReadFull(session.Reader, data)
				if e == nil && string(data) != "payload" {
					e = errors.New("lost prefetched target data")
				}
				session.Conn.Close()
			}
			errs <- e
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	st := s.Stats()
	if f.rejected.Load() != 0 || st.Active != 0 || st.Waiting != 0 || st.Foreground != 20 || st.Background != 2 {
		t.Fatal("budget not shared", f.rejected.Load(), st)
	}
}
func TestHandshakePermitReleasedBeforeTargetAndPrepareWait(t *testing.T) {
	f := newHandshakeFixture(t, true)
	releaseBarrier := sync.OnceFunc(func() { close(f.barrier) })
	defer releaseBarrier()
	s := handshake.New(handshake.Options{Rate: 1000, Burst: 2, Concurrent: 1, Background: 1, Queue: 4, MaxWait: time.Second})
	ctx, cancel := context.WithTimeout(handshake.WithScheduler(context.Background(), s), 2*time.Second)
	defer cancel()
	done := make(chan error, 2)
	go func() {
		session, e := openRemote(ctx, f.cfg, "target.invalid:443", nil)
		if e == nil {
			session.Conn.Close()
		}
		done <- e
	}()
	go func() {
		entry, e := preconnect.NewPreparer(f.cfg, s)(ctx)
		if e == nil {
			closeUnusedRemote(entry.Conn)
		}
		done <- e
	}()
	for range 2 {
		select {
		case <-f.auth:
		case <-ctx.Done():
			t.Fatal("target or PREPARE wait retained handshake permit")
		}
	}
	// Both authenticated while final target/READY responses were withheld.
	releaseBarrier()
	for range 2 {
		if e := <-done; e != nil {
			t.Fatal(e)
		}
	}
}

func TestQueuedSetupCancellationDoesNotDial(t *testing.T) {
	s := handshake.New(handshake.Options{Rate: 1, Burst: 1, Concurrent: 1, Background: 1, Queue: 2, MaxWait: time.Second})
	release, _, err := s.Acquire(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(handshake.WithScheduler(context.Background(), s), 10*time.Millisecond)
	defer cancel()
	session, err := openRemote(ctx, &config.ClientConfig{RemoteAddr: "node.invalid:443"}, "target.invalid:443", nil)
	if !errors.Is(err, context.DeadlineExceeded) || session.Stage != "handshake_queue" || session.Conn != nil || session.Dial.TCPDuration != 0 || s.Stats().Waiting != 0 || s.Stats().Foreground != 1 {
		t.Fatal(err, session, s.Stats())
	}
}
