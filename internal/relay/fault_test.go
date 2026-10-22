package relay

import (
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
)

func TestFaultUsesRootSocketAndPreservesWrappedErrors(t *testing.T) {
	a, ap := newTCPPair(t)
	b, bp := newTCPPair(t)
	setTestDeadlines(t, a, ap, b, bp)
	readA := &net.OpError{Op: "read", Net: "tcp", Source: a.LocalAddr(), Addr: a.RemoteAddr(), Err: syscall.ECONNRESET}
	writeB := &net.OpError{Op: "write", Net: "tcp", Source: b.LocalAddr(), Addr: b.RemoteAddr(), Err: syscall.EPIPE}
	for _, tc := range []struct {
		name, phase, op, endpoint string
		err                       error
		dir                       direction
	}{
		{"source read", "copy", "read", "a", readA, directionAToB},
		{"destination write", "copy", "write", "b", writeB, directionAToB},
		{"nested ReadFrom", "copy", "read", "a", &net.OpError{Op: "readfrom", Addr: b.RemoteAddr(), Err: readA}, directionAToB},
		{"ambiguous join", "copy", "unknown", "unknown", errors.Join(readA, writeB), directionAToB},
		{"uneven ambiguous join", "copy", "unknown", "unknown", errors.Join(readA, fmt.Errorf("other: %w", writeB)), directionAToB},
		{"unknown ReadFrom", "copy", "unknown", "unknown", &net.OpError{Op: "readfrom", Addr: b.RemoteAddr(), Err: io.ErrUnexpectedEOF}, directionAToB},
		{"half close upload", "half_close", "close_write", "b", syscall.ENOTCONN, directionAToB},
		{"half close download", "half_close", "close_write", "a", syscall.ENOTCONN, directionBToA},
		{"plain error", "copy", "unknown", "unknown", io.ErrUnexpectedEOF, directionBToA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := describeFault(tc.err, tc.phase, tc.dir, a, b)
			if f.Operation != tc.op || f.Endpoint != tc.endpoint {
				t.Fatalf("fault=%+v", f)
			}
			if f.Endpoint == "a" && (f.LocalAddr != a.LocalAddr().String() || f.RemoteAddr != a.RemoteAddr().String()) {
				t.Fatalf("wrong socket addresses: %+v", f)
			}
		})
	}
	// Exercise the coordinator too: the deliberate reverse interruption must not
	// replace the read error, direction, endpoint, or OS errno.
	r := waitForResult(t, startRelay(a, failingReader{readA}, b, b))
	if !errors.Is(r.Err, syscall.ECONNRESET) || r.FailureDirection != "up" || r.Fault.Endpoint != "a" || r.Fault.Operation != "read" || r.Fault.Errno != uint64(syscall.ECONNRESET) {
		t.Fatalf("root fault lost: %+v", r)
	}
}

func TestFaultRejectsUnmatchedAndOverlongErrorChains(t *testing.T) {
	a, ap := newTCPPair(t)
	b, bp := newTCPPair(t)
	setTestDeadlines(t, a, ap, b, bp)
	err := error(&net.OpError{Op: "read", Source: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1}, Err: syscall.ECONNRESET})
	if f := describeFault(err, "copy", directionAToB, a, b); f.Endpoint != "unknown" {
		t.Fatal(f)
	}
	for range 40 {
		err = fmt.Errorf("wrapped: %w", err)
	}
	if f := describeFault(err, "copy", directionAToB, a, b); f.Operation != "unknown" || f.Endpoint != "unknown" {
		t.Fatal(f)
	}
}
