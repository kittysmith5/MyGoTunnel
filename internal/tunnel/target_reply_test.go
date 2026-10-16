package tunnel

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestTargetReplyHasIndependentWriteBudget(t *testing.T) {
	for _, cause := range []error{nil, context.DeadlineExceeded} {
		t.Run(map[bool]string{true: "error", false: "success"}[cause != nil], func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			if err := a.SetDeadline(time.Now().Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- SendTargetResult(a, cause) }()
			b.SetReadDeadline(time.Now().Add(2 * time.Second))
			line, err := ReadLine(bufio.NewReader(b))
			want := "OK"
			if cause != nil {
				want = "ERR TIMEOUT"
			}
			if err != nil || line != want {
				t.Fatalf("reply after expired control deadline = %q %v", line, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			// Refreshing the write budget must not silently extend reads.
			var scratch [1]byte
			_, err = a.Read(scratch[:])
			var network net.Error
			if !errors.As(err, &network) || !network.Timeout() {
				t.Fatalf("read deadline was extended: %v", err)
			}
		})
	}
}

func TestTargetReplyBlockedPeerIsBounded(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	started := time.Now()
	err := SendTargetResult(a, context.DeadlineExceeded)
	var network net.Error
	if !errors.As(err, &network) || !network.Timeout() {
		t.Fatalf("non-reading peer = %v", err)
	}
	if elapsed := time.Since(started); elapsed < ControlReplyTimeout || elapsed > 4*ControlReplyTimeout {
		t.Fatalf("reply duration = %v", elapsed)
	}
}

func TestLegacyDatagramBodyEOFIsTruncated(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire string
		want error
	}{
		{"boundary", "", io.EOF},
		{"prefix", "\x00", io.ErrUnexpectedEOF},
		{"missing body", "\x00\x05", io.ErrUnexpectedEOF},
		{"partial body", "\x00\x05x", io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ReadDatagram(strings.NewReader(tc.wire))
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
}
