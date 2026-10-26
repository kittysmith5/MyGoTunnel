package relay

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

func TestObservedRelayKeepsPrebufferAndHalfClose(t *testing.T) {
	a, ap := newTCPPair(t)
	b, bp := newTCPPair(t)
	setTestDeadlines(t, a, ap, b, bp)
	// Prebuffer downlink before relay entry. It must still be observed and sent.
	if _, e := bp.Write([]byte("early")); e != nil {
		t.Fatal(e)
	}
	reader := bufio.NewReader(b)
	if _, e := reader.Peek(5); e != nil {
		t.Fatal(e)
	}
	events := make(chan string, 4)
	done := make(chan Result, 1)
	go func() {
		done <- CopyBidirectionalObservedContext(context.Background(), a, a, b, reader, func(s string, d time.Duration) {
			if d < 0 {
				t.Error("negative first data")
			}
			events <- s
		})
	}()
	if _, e := ap.Write([]byte("request")); e != nil {
		t.Fatal(e)
	}
	ap.CloseWrite()
	up, e := io.ReadAll(bp)
	if e != nil || string(up) != "request" {
		t.Fatal(string(up), e)
	}
	if _, e = bp.Write([]byte("late")); e != nil {
		t.Fatal(e)
	}
	bp.CloseWrite()
	down, e := io.ReadAll(ap)
	if e != nil || string(down) != "earlylate" {
		t.Fatal(string(down), e)
	}
	r := waitForResult(t, done)
	if r.Err != nil || !r.AToB.FirstByteSeen || !r.BToA.FirstByteSeen {
		t.Fatal(r)
	}
	if len(events) != 2 {
		t.Fatal("not exactly two observations", len(events))
	}
}

type countedReaderFrom struct {
	bytes.Buffer
	called bool
}

func (w *countedReaderFrom) ReadFrom(r io.Reader) (int64, error) {
	w.called = true
	return w.Buffer.ReadFrom(r)
}
func TestFirstCopyPreservesReaderFrom(t *testing.T) {
	first := &firstCopy{started: time.Now()}
	w := &countedReaderFrom{}
	r := bufio.NewReaderSize(bytes.NewBufferString("payload"), 16)
	if _, e := io.Copy(firstWriter{w, first}, r); e != nil {
		t.Fatal(e)
	}
	// Direct ReadFrom is also used by net.TCPConn after bufio's initial buffer.
	if _, e := (firstWriter{w, first}).ReadFrom(bytes.NewBufferString("more")); e != nil {
		t.Fatal(e)
	}
	if !w.called || !first.seen || w.String() != "payloadmore" {
		t.Fatal(w.String())
	}
}
