package setupwatch

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peer, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := listener.AcceptTCP()
	if err != nil {
		peer.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(); peer.Close() })
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return conn, peer
}

func TestRSTCancelsAfterEarlyPayload(t *testing.T) {
	conn, peer := tcpPair(t)
	reader := bufio.NewReader(conn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watch := Start(conn, reader, cancel)
	if _, err := peer.Write([]byte("early payload")); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("RST did not cancel setup")
	}
	if err := watch.Stop(time.Time{}); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("Stop error = %v, want reset", err)
	}
}

func TestFINPreservesPayloadAndReverseWrites(t *testing.T) {
	conn, peer := tcpPair(t)
	reader := bufio.NewReader(conn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watch := Start(conn, reader, cancel)
	const payload = "request before setup\x00\n"
	if _, err := io.WriteString(peer, payload); err != nil {
		t.Fatal(err)
	}
	if err := peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-watch.done:
	case <-time.After(time.Second):
		t.Fatal("FIN did not finish watcher")
	}
	if err := watch.Stop(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil {
		t.Fatal("FIN canceled setup")
	}
	got, err := io.ReadAll(reader)
	if err != nil || string(got) != payload {
		t.Fatalf("preserved payload = %q, %v", got, err)
	}
	if _, err := io.WriteString(conn, "reply"); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(peer)
	if err != nil || string(got) != "reply" {
		t.Fatalf("reverse payload = %q, %v", got, err)
	}
}

func TestStopHandsOffBlockedReaderAndRestoresDeadline(t *testing.T) {
	conn, peer := tcpPair(t)
	reader := bufio.NewReader(conn)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watch := Start(conn, reader, cancel)
	var callers sync.WaitGroup
	for range 8 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			if err := watch.Stop(time.Time{}); err != nil {
				t.Error(err)
			}
		}()
	}
	callers.Wait()
	if ctx.Err() != nil {
		t.Fatal("Stop canceled setup")
	}
	if _, err := io.WriteString(peer, "after handoff"); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("after handoff"))
	if _, err := io.ReadFull(reader, got); err != nil || string(got) != "after handoff" {
		t.Fatalf("handoff payload = %q, %v", got, err)
	}
}

func TestBufferLimitPreservesAllPayload(t *testing.T) {
	conn, peer := tcpPair(t)
	reader := bufio.NewReaderSize(conn, 32)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watch := Start(conn, reader, cancel)
	want := bytes.Repeat([]byte{0x42}, 128)
	if _, err := peer.Write(want); err != nil {
		t.Fatal(err)
	}
	select {
	case <-watch.done:
	case <-time.After(time.Second):
		t.Fatal("watcher did not stop at buffer limit")
	}
	if err := watch.Stop(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if reader.Buffered() != reader.Size() || ctx.Err() != nil {
		t.Fatalf("buffered=%d limit=%d context=%v", reader.Buffered(), reader.Size(), ctx.Err())
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(reader, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("bounded handoff lost payload: %v", err)
	}
}

type deadlineErrorConn struct {
	net.Conn
	err     error
	failAt  int
	calls   int
	reading chan struct{}
	once    sync.Once
}

func (c *deadlineErrorConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.reading) })
	return c.Conn.Read(p)
}

func (c *deadlineErrorConn) SetReadDeadline(deadline time.Time) error {
	c.calls++
	if c.calls == c.failAt {
		return c.err
	}
	return c.Conn.SetReadDeadline(deadline)
}

func TestStopReportsDeadlineErrorsAndWaitsForReader(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(map[int]string{1: "interrupt", 2: "restore"}[failAt], func(t *testing.T) {
			conn, peer := net.Pipe()
			defer peer.Close()
			defer conn.Close()
			failure := errors.New("deadline failed")
			wrapped := &deadlineErrorConn{Conn: conn, err: failure, failAt: failAt, reading: make(chan struct{})}
			watch := Start(wrapped, bufio.NewReader(wrapped), nil)
			<-wrapped.reading
			if err := watch.Stop(time.Time{}); !errors.Is(err, failure) {
				t.Fatalf("Stop = %v, want deadline failure", err)
			}
			select {
			case <-watch.done:
			default:
				t.Fatal("Stop returned before reader exited")
			}
		})
	}
}
