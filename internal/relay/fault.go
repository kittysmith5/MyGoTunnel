package relay

import (
	"errors"
	"net"
	"syscall"
)

// Fault describes the socket that reported the root error, not a network-path
// diagnosis. Unknown fields stay explicit; no Reader/Writer wrappers are added.
type Fault struct {
	Operation, Endpoint   string // read/write/close_write/unknown; a/b/unknown
	LocalAddr, RemoteAddr string
	Errno                 uint64 // OS errno, zero when unavailable
}

func describeFault(err error, phase string, dir direction, a, b net.Conn) Fault {
	f := Fault{Operation: "unknown", Endpoint: "unknown"}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		f.Errno = uint64(errno)
	}
	var conn net.Conn
	if phase == "half_close" {
		// The operation is known from our call site even without a net.OpError.
		f.Operation = "close_write"
		f.Endpoint, conn = "b", b
		if dir == directionBToA {
			f.Endpoint, conn = "a", a
		}
	} else {
		// io.Copy may nest a source read failure inside a destination ReadFrom
		// error. Inspect the deepest OpError; never assume ReadFrom means write.
		deepest := socketOperation(err)
		if deepest != nil && (deepest.Op == "read" || deepest.Op == "write") {
			f.Operation = deepest.Op
			matchA, matchB := matchesSocket(deepest, a), matchesSocket(deepest, b)
			if matchA != matchB {
				f.Endpoint, conn = "a", a
				if matchB {
					f.Endpoint, conn = "b", b
				}
			}
		}
	}
	if conn != nil {
		if addr := conn.LocalAddr(); addr != nil {
			f.LocalAddr = addr.String()
		}
		if addr := conn.RemoteAddr(); addr != nil {
			f.RemoteAddr = addr.String()
		}
	}
	return f
}

// Follow only a single, bounded error chain. Multiple joined causes cannot be
// assigned to one socket reliably, even if one branch has more wrappers.
func socketOperation(err error) *net.OpError {
	var deepest *net.OpError
	for depth := 0; err != nil && depth < 32; depth++ {
		if op, ok := err.(*net.OpError); ok {
			deepest = op
		}
		switch e := err.(type) {
		case interface{ Unwrap() []error }:
			var next error
			for _, child := range e.Unwrap() {
				if child != nil {
					if next != nil {
						return nil
					}
					next = child
				}
			}
			err = next
		case interface{ Unwrap() error }:
			err = e.Unwrap()
		default:
			err = nil
		}
	}
	if err != nil {
		return nil
	}
	return deepest
}

func matchesSocket(op *net.OpError, conn net.Conn) bool {
	if conn == nil || (op.Source == nil && op.Addr == nil) {
		return false
	}
	same := func(want, got net.Addr) bool {
		return want == nil || (got != nil && want.Network() == got.Network() && want.String() == got.String())
	}
	return same(op.Source, conn.LocalAddr()) && same(op.Addr, conn.RemoteAddr())
}
