package preconnect

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/quicudp"
	"mygotunnel/internal/tunnel"
)

type quicPrepareFixture struct {
	listener net.Listener
	client   *datagram.Resources
	server   *datagram.Resources
	cfg      *config.ClientConfig
	accepted atomic.Int64
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
	done     chan struct{}
	stop     sync.Once
}

func newQUICPrepareFixture(t *testing.T, handle func(net.Conn, *bufio.Reader) error) *quicPrepareFixture {
	t.Helper()
	certSource := httptest.NewTLSServer(nil)
	cert := certSource.TLS.Certificates[0]
	certSource.Close()
	f := &quicPrepareFixture{
		client: datagram.NewResources(16, 4<<20), server: datagram.NewResources(16, 4<<20),
		conns: make(map[net.Conn]struct{}), done: make(chan struct{}),
	}
	var err error
	f.listener, err = quicudp.Listen("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, NextProtos: []string{quicudp.ALPN}, SessionTicketsDisabled: true,
	}, f.server, time.Second, 16)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(cert.Certificate[0])
	f.cfg = &config.ClientConfig{RemoteAddr: f.listener.Addr().String(), AuthToken: "quic-prepare-test",
		CertificateFingerprint: hex.EncodeToString(pin[:]), UDPTransport: "quic"}
	go func() {
		defer close(f.done)
		for {
			conn, err := f.listener.Accept()
			if err != nil {
				return
			}
			f.accepted.Add(1)
			f.mu.Lock()
			f.conns[conn] = struct{}{}
			f.mu.Unlock()
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				defer conn.Close()
				defer func() { f.mu.Lock(); delete(f.conns, conn); f.mu.Unlock() }()
				_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
				if err := handle(conn, bufio.NewReader(conn)); err != nil {
					t.Errorf("QUIC fixture: %v", err)
				}
			}()
		}
	}()
	t.Cleanup(func() {
		f.close()
		f.client.Close()
		f.server.Close()
	})
	return f
}

func (f *quicPrepareFixture) close() {
	f.stop.Do(func() {
		_ = f.listener.Close()
		<-f.done
		f.mu.Lock()
		conns := make([]net.Conn, 0, len(f.conns))
		for conn := range f.conns {
			conns = append(conns, conn)
		}
		f.mu.Unlock()
		for _, conn := range conns {
			_ = conn.Close()
		}
		f.wg.Wait()
	})
}

func quicPrepareAuth(conn net.Conn, reader *bufio.Reader) error {
	auth, err := tunnel.ReadLine(reader)
	if err != nil {
		return err
	}
	if auth != "AUTH quic-prepare-test" {
		conn.(*quicudp.Conn).RejectAuthentication()
		return tunnel.ErrAuthRejected
	}
	if err := tunnel.SendOK(conn); err != nil {
		return err
	}
	command, err := tunnel.ReadLine(reader)
	if err != nil {
		return err
	}
	if command != "PREPARE ACK" {
		return fmt.Errorf("unexpected prepare command")
	}
	return nil
}

func TestQUICPreparerPoolTransfersControlAndRetainsTakenOwnership(t *testing.T) {
	var auths, activated atomic.Int64
	f := newQUICPrepareFixture(t, func(conn net.Conn, reader *bufio.Reader) error {
		if err := quicPrepareAuth(conn, reader); err != nil {
			return err
		}
		auths.Add(1)
		if err := tunnel.SendReadyWithAck(conn); err != nil {
			return err
		}
		command, err := tunnel.ReadLine(reader)
		if err != nil {
			return nil // Pool shutdown closes unused connections.
		}
		if command != "UDP" {
			return fmt.Errorf("unexpected association command")
		}
		activated.Add(1)
		if err := tunnel.SendAcknowledged(conn); err != nil {
			return err
		}
		conn.(*quicudp.Conn).EnableDatagrams()
		if err := tunnel.SendOK(conn); err != nil {
			return err
		}
		packet, err := conn.(*quicudp.Conn).ReadPacket()
		if err != nil {
			return err
		}
		defer packet.Release()
		if err := conn.(*quicudp.Conn).WritePacket(packet.Data); err != nil {
			return err
		}
		_, _ = conn.(*quicudp.Conn).ReadPacket()
		return nil
	})
	pool, err := New(Options{Size: 1, MaxSize: 1}, NewQUICPreparer(f.cfg, f.client), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	original := idle(t, pool, 1)
	if original.QUICDuration <= 0 || original.DialTimings.TLSDuration != 0 || !original.CommandACK {
		t.Fatal("QUIC preparation timing or command negotiation was lost")
	}
	if err := original.Conn.(*quicudp.Conn).WritePacket([]byte("not authorized")); !errors.Is(err, quicudp.ErrNotAuthorized) {
		t.Fatal("prepared connection allowed business datagrams", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	entry := pool.Take(ctx)
	if entry != original || entry.Reader != original.Reader {
		t.Fatal("passive monitor did not transfer the original reader")
	}
	// A handed-off association must survive closing the pool and its refill.
	pool.Close()
	defer entry.Conn.Close()
	if err := entry.Conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SendUDPAssociate(entry.Conn); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{tunnel.CommandAcknowledged, "OK"} {
		response, err := tunnel.ReadLine(entry.Reader)
		if err != nil || response != expected {
			t.Fatalf("prepared command response %q: %v", response, err)
		}
	}
	if err := entry.Conn.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	packets := entry.Conn.(*quicudp.Conn)
	packets.EnableDatagrams()
	if err := packets.WritePacket([]byte("association payload")); err != nil {
		t.Fatal(err)
	}
	packet, err := packets.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if string(packet.Data) != "association payload" {
		t.Fatal("association payload changed")
	}
	packet.Release()
	_ = entry.Conn.Close()
	f.close()
	if auths.Load() < 1 || activated.Load() != 1 {
		t.Fatalf("authentication/activation counts %d/%d", auths.Load(), activated.Load())
	}
	if stats := f.client.Stats(); stats.Sockets != 0 || stats.BufferBytes != stats.CachedBytes {
		t.Fatal("QUIC pool retained client resources", stats)
	}
	deadline := time.Now().Add(time.Second)
	for f.server.Stats().Sockets != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if stats := f.server.Stats(); stats.Sockets != 0 || stats.BufferBytes != stats.CachedBytes {
		t.Fatal("QUIC pool retained server resources", stats)
	}
}

func TestQUICPreparerRejectsAuthenticationAndUnsupportedResponses(t *testing.T) {
	for _, mode := range []string{"auth", "unsupported", "busy", "limit close", "closed", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			f := newQUICPrepareFixture(t, func(conn net.Conn, reader *bufio.Reader) error {
				if err := quicPrepareAuth(conn, reader); err != nil {
					if mode == "auth" && errors.Is(err, tunnel.ErrAuthRejected) {
						return nil
					}
					return err
				}
				switch mode {
				case "unsupported":
					_, _ = io.WriteString(conn, "ERR\n")
				case "busy":
					_ = tunnel.SendBusy(conn)
				case "limit close":
					conn.(*quicudp.Conn).RejectLimit()
					return nil
				case "closed":
					// Let AUTH's OK reach the peer before emulating an old
					// server that closes on its unknown PREPARE command.
					time.Sleep(30 * time.Millisecond)
					return nil
				case "timeout":
					// Withhold READY until the caller's shorter deadline.
					// A timeout must not become an unsupported result.
				}
				_, _ = io.Copy(io.Discard, reader)
				return nil
			})
			if mode == "auth" {
				f.cfg.AuthToken = "invalid-token"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if mode == "timeout" {
				var deadlineCancel context.CancelFunc
				ctx, deadlineCancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer deadlineCancel()
			}
			entry, err := NewQUICPreparer(f.cfg, f.client)(ctx)
			if entry != nil || err == nil {
				t.Fatalf("unexpected preparation: %v %v", entry, err)
			}
			switch mode {
			case "auth":
				if !errors.Is(err, tunnel.ErrAuthRejected) {
					t.Fatal("authentication close classification lost", err)
				}
			case "unsupported", "closed":
				if !errors.Is(err, ErrUnsupported) {
					t.Fatal("unsupported capability not recognized", err)
				}
			case "busy", "limit close":
				if !errors.Is(err, ErrBusy) {
					t.Fatal("idle capacity rejection not recognized", err)
				}
			case "timeout":
				var timeout net.Error
				if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, os.ErrDeadlineExceeded) && !(errors.As(err, &timeout) && timeout.Timeout()) {
					t.Fatal("preparation timeout classification lost", err)
				}
			}
			f.close()
			if stats := f.client.Stats(); stats.Sockets != 0 || stats.BufferBytes != stats.CachedBytes {
				t.Fatal("failed preparation retained resources", stats)
			}
		})
	}
}

func TestQUICPreparerWrongPinAndCancellation(t *testing.T) {
	t.Run("wrong pin", func(t *testing.T) {
		f := newQUICPrepareFixture(t, func(conn net.Conn, reader *bufio.Reader) error {
			// The peer must reject our certificate before any AUTH bytes.
			line, err := tunnel.ReadLine(reader)
			if err == nil || line != "" {
				return fmt.Errorf("untrusted peer reached AUTH")
			}
			return nil
		})
		f.cfg.CertificateFingerprint = strings.Repeat("00", sha256.Size)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		entry, err := NewQUICPreparer(f.cfg, f.client)(ctx)
		if err == nil || entry != nil {
			t.Fatal("wrong pin accepted")
		}
		f.close()
		if s := f.client.Stats(); s.Sockets != 0 {
			t.Fatal("wrong pin leaked socket", s)
		}
	})
	t.Run("cancel stalled authentication", func(t *testing.T) {
		started := make(chan struct{})
		f := newQUICPrepareFixture(t, func(conn net.Conn, reader *bufio.Reader) error {
			if _, err := tunnel.ReadLine(reader); err != nil {
				return err
			}
			close(started)
			_, _ = io.Copy(io.Discard, reader)
			return nil
		})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		result := make(chan error, 1)
		go func() {
			_, err := NewQUICPreparer(f.cfg, f.client)(ctx)
			result <- err
		}()
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("stalled authentication was not reached")
		}
		cancel()
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost", err)
			}
		case <-time.After(time.Second):
			t.Fatal("cancellation did not join preparation")
		}
		if stats := f.client.Stats(); stats.Sockets != 0 || stats.BufferBytes != stats.CachedBytes {
			t.Fatal("cancellation returned before resource cleanup", stats)
		}
	})
}

func TestQUICPreparerSharesProcessSocketBudget(t *testing.T) {
	f := newQUICPrepareFixture(t, func(conn net.Conn, reader *bufio.Reader) error {
		if err := quicPrepareAuth(conn, reader); err != nil {
			return err
		}
		if err := tunnel.SendReadyWithAck(conn); err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, reader)
		return nil
	})
	resources := datagram.NewResources(2, 1<<20)
	defer resources.Close()
	factory := NewQUICPreparer(f.cfg, resources)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	first, err := factory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Conn.Close()
	second, err := factory(ctx)
	if second != nil || !errors.Is(err, datagram.ErrResourceLimit) {
		t.Fatal("preparation bypassed the shared socket budget", err)
	}
	if stats := resources.Stats(); stats.Sockets != 1 || stats.SocketRejected != 1 {
		t.Fatal("unexpected prepared socket accounting", stats)
	}
	if !resources.AcquireSocket() {
		t.Fatal("background preparation exhausted foreground relay headroom")
	}
	resources.ReleaseSocket()
	_ = first.Conn.Close()
	third, err := factory(ctx)
	if err != nil {
		t.Fatal("released socket was not available for refill", err)
	}
	_ = third.Conn.Close()
	if stats := resources.Stats(); stats.Sockets != 0 || stats.BufferBytes != stats.CachedBytes {
		t.Fatal("preparation retained process resources", stats)
	}
}

func TestQUICPoolLowBudgetLeavesRelaySlotForAssociation(t *testing.T) {
	f := newQUICPrepareFixture(t, func(conn net.Conn, reader *bufio.Reader) error {
		if err := quicPrepareAuth(conn, reader); err != nil {
			return err
		}
		if err := tunnel.SendReadyWithAck(conn); err != nil {
			return err
		}
		command, err := tunnel.ReadLine(reader)
		if err != nil {
			return nil
		}
		if command != "UDP" {
			return fmt.Errorf("unexpected low-budget association command")
		}
		if _, err := io.WriteString(conn, "ACK\nOK\n"); err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, reader)
		return nil
	})
	resources := datagram.NewResources(2, 1<<20)
	defer resources.Close()
	// Request two background entries against a total budget of two sockets.
	// Admission must reserve one relay slot even when both fills race.
	pool, err := New(Options{Size: 2, MaxSize: 2}, NewQUICPreparer(f.cfg, resources), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	_ = idle(t, pool, 1)
	if !resources.AcquireSocket() {
		t.Fatal("ready background pool starved the foreground relay")
	}
	defer resources.ReleaseSocket()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	entry := pool.Take(ctx)
	if entry == nil {
		t.Fatal("low-budget pool failed to hand off its ready connection")
	}
	defer entry.Conn.Close()
	if err := entry.Conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SendUDPAssociate(entry.Conn); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"ACK", "OK"} {
		response, err := tunnel.ReadLine(entry.Reader)
		if err != nil || response != expected {
			t.Fatalf("low-budget association failed: %q %v", response, err)
		}
	}
	if stats := resources.Stats(); stats.Sockets != 2 {
		t.Fatal("association did not retain its relay and QUIC sockets", stats)
	}
}
