package relay

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
)

type notifyTrackingConn struct {
	net.Conn
	closeCalls atomic.Int32
}

func (c *notifyTrackingConn) NetConn() net.Conn { return c.Conn }
func (c *notifyTrackingConn) Close() error {
	c.closeCalls.Add(1)
	return c.Conn.Close()
}
func (c *notifyTrackingConn) CloseWrite() error {
	return c.Conn.(interface{ CloseWrite() error }).CloseWrite()
}

func TestContextAbortClosesUnderlyingTransportsAfterHalfClose(t *testing.T) {
	a, ap := newTCPPair(t)
	b, bp := newTCPPair(t)
	setTestDeadlines(t, a, ap, b, bp)
	wrappedA, wrappedB := &notifyTrackingConn{Conn: a}, &notifyTrackingConn{Conn: b}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan Result, 1)
	go func() { done <- CopyBidirectionalContext(ctx, wrappedA, wrappedA, wrappedB, wrappedB) }()
	if err := ap.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(bp); err != nil {
		t.Fatal(err)
	}
	cancel()
	result := waitForResult(t, done)
	if result.Err == nil || result.FailureDirection != "down" {
		t.Fatalf("reverse source was not aborted: %+v", result)
	}
	if wrappedA.closeCalls.Load() != 0 || wrappedB.closeCalls.Load() != 0 {
		t.Fatal("force abort attempted TLS close notification")
	}
}

func TestContextRelayStillDrainsNormalHalfClose(t *testing.T) {
	a, ap := newTCPPair(t)
	b, bp := newTCPPair(t)
	setTestDeadlines(t, a, ap, b, bp)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan Result, 1)
	go func() { done <- CopyBidirectionalContext(ctx, a, a, b, b) }()
	if _, err := io.WriteString(ap, "request"); err != nil {
		t.Fatal(err)
	}
	if err := ap.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(bp); err != nil || string(got) != "request" {
		t.Fatalf("request=%q error=%v", got, err)
	}
	if _, err := io.WriteString(bp, "response after EOF"); err != nil {
		t.Fatal(err)
	}
	if err := bp.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(ap); err != nil || string(got) != "response after EOF" {
		t.Fatalf("response=%q error=%v", got, err)
	}
	result := waitForResult(t, done)
	if result.Err != nil || result.AToB.Bytes != 7 || result.BToA.Bytes != int64(len("response after EOF")) {
		t.Fatalf("normal drain=%+v", result)
	}
}

func TestAlreadyCanceledContextAbortsRawTransportsWithoutNotify(t *testing.T) {
	a, ap := newTCPPair(t)
	b, bp := newTCPPair(t)
	setTestDeadlines(t, a, ap, b, bp)
	wrappedA, wrappedB := &notifyTrackingConn{Conn: a}, &notifyTrackingConn{Conn: b}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := CopyBidirectionalContext(ctx, wrappedA, wrappedA, wrappedB, wrappedB)
	if result.Err == nil {
		t.Fatal("canceled relay did not report interruption")
	}
	if wrappedA.closeCalls.Load() != 0 || wrappedB.closeCalls.Load() != 0 {
		t.Fatal("force abort attempted TLS close notification")
	}
}
