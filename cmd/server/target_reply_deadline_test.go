package main

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/tunnel"
)

type targetReplyDeadlineConn struct {
	net.Conn
	controlDeadlines chan time.Time
	replyDeadlines   chan time.Time
}

func (c *targetReplyDeadlineConn) SetDeadline(deadline time.Time) error {
	err := c.Conn.SetDeadline(deadline)
	c.controlDeadlines <- deadline
	return err
}

func (c *targetReplyDeadlineConn) SetWriteDeadline(deadline time.Time) error {
	err := c.Conn.SetWriteDeadline(deadline)
	c.replyDeadlines <- deadline
	return err
}

func TestTargetErrorReplySurvivesRealControlDeadline(t *testing.T) {
	// Keep the real 20-second production deadline. A resolver held until its
	// context expires forces target failure exactly at that boundary.
	previousResolver := net.DefaultResolver
	resolving := make(chan struct{}, 4)
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		select {
		case resolving <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	t.Cleanup(func() { net.DefaultResolver = previousResolver })
	server, client := net.Pipe()
	tracked := &targetReplyDeadlineConn{Conn: server, controlDeadlines: make(chan time.Time, 8), replyDeadlines: make(chan time.Time, 8)}
	parent, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleTunnelContext(parent, tracked, &config.ServerConfig{AuthToken: "reply-test-token"}, slog.New(slog.NewTextHandler(io.Discard, nil)), func() {}, nil)
	}()
	t.Cleanup(func() {
		cancel()
		client.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("target deadline handler did not exit")
		}
	})
	client.SetDeadline(time.Now().Add(tunnel.ControlTimeout + 5*time.Second))
	if err := tunnel.SendAuth(client, "reply-test-token"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	if line, err := tunnel.ReadLine(reader); err != nil || line != "OK" {
		t.Fatal(line, err)
	}
	var controlDeadline time.Time
	for controlDeadline.IsZero() {
		select {
		case deadline := <-tracked.controlDeadlines:
			if time.Until(deadline) > tunnel.ControlTimeout/2 {
				controlDeadline = deadline
			}
		case <-time.After(time.Second):
			t.Fatal("control deadline was not installed")
		}
	}
	<-time.After(time.Until(controlDeadline) - 250*time.Millisecond)
	if err := tunnel.SendConnect(client, "control-deadline.invalid:12345"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-resolving:
	case <-time.After(time.Second):
		t.Fatal("controlled resolver did not start")
	}
	line, err := tunnel.ReadLine(reader)
	if err != nil || (line != "ERR DNS" && line != "ERR TIMEOUT") {
		t.Fatalf("expired control reply = %q %v, want typed timeout/DNS error", line, err)
	}
	select {
	case replyDeadline := <-tracked.replyDeadlines:
		if !replyDeadline.After(controlDeadline) || time.Until(replyDeadline) <= 0 || time.Until(replyDeadline) > tunnel.ControlReplyTimeout {
			t.Fatalf("target reply did not receive an independent bounded write deadline: control=%v reply=%v", controlDeadline, replyDeadline)
		}
	default:
		t.Fatal("target reply reused the expired control deadline")
	}
	if line, err := tunnel.ReadLine(reader); err != io.EOF || line != "" {
		t.Fatalf("target failure did not close after reply: %q %v", line, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("target failure handler did not finish")
	}
}

func TestPreparedSetupRejectionWriteIsBoundedWithoutReader(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	idleSlots := make(chan struct{}, 1)
	var setupReleases, resumeAttempts atomic.Int32
	go func() {
		defer close(done)
		handleTunnelWithPool(server, &config.ServerConfig{AuthToken: "reply-test-token"}, slog.New(slog.NewTextHandler(io.Discard, nil)), func() { setupReleases.Add(1) }, &serverPoolOptions{
			idleSlots: idleSlots, resumeSetup: func() bool { resumeAttempts.Add(1); return false },
		})
	}()
	t.Cleanup(func() {
		client.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("blocked setup rejection handler did not exit")
		}
	})
	client.SetDeadline(time.Now().Add(3 * time.Second))
	if err := tunnel.SendPrepareWithAck(client, "reply-test-token"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	for _, want := range []string{"OK", tunnel.PreparedAckReady} {
		if line, err := tunnel.ReadLine(reader); err != nil || line != want {
			t.Fatal(line, err)
		}
	}
	started := time.Now()
	if err := tunnel.SendUDPAssociate(client); err != nil {
		t.Fatal(err)
	}
	// Never consume ERR LIMIT. A zero-capacity pipe makes this write block,
	// proving the rejection cannot inherit the 60-second prepared deadline.
	select {
	case <-done:
	case <-time.After(tunnel.ControlReplyTimeout + time.Second):
		t.Fatal("setup rejection write exceeded independent reply budget")
	}
	if elapsed := time.Since(started); elapsed < tunnel.ControlReplyTimeout/2 {
		t.Fatalf("rejection did not exercise a blocked reply write: %v", elapsed)
	}
	if len(idleSlots) != 0 || setupReleases.Load() != 1 || resumeAttempts.Load() != 1 {
		t.Fatalf("rejection leaked capacity: idle=%d releases=%d reacquire=%d", len(idleSlots), setupReleases.Load(), resumeAttempts.Load())
	}
}
