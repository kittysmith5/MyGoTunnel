package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// ErrHalfCloseUnsupported indicates that a relay endpoint cannot independently
// close its write side while continuing to read the reverse stream.
var ErrHalfCloseUnsupported = errors.New("connection does not support CloseWrite")

// DirectionResult describes one direction of a bidirectional relay.
type DirectionResult struct {
	Bytes             int64
	Err               error
	Phase             string
	FirstByteSeen     bool
	FirstByteDuration time.Duration
}

// Result contains transfer statistics for both directions and the error that
// caused the relay to stop. AToB is the upload direction at both current call
// sites, while BToA is the download direction.
type Result struct {
	AToB             DirectionResult
	BToA             DirectionResult
	Err              error
	FailureDirection string
	FailurePhase     string
	Fault            Fault
}

type closeWriter interface {
	CloseWrite() error
}

type direction uint8

const (
	directionAToB direction = iota
	directionBToA
)

type copyResult struct {
	direction direction
	result    DirectionResult
}

// CopyBidirectional relays both directions until they have both reached EOF.
// A normal EOF half-closes the destination and allows the reverse stream to
// drain. A copy or half-close error interrupts both endpoints so the other
// goroutine can exit before this function returns.
func CopyBidirectional(a net.Conn, aReader io.Reader, b net.Conn, bReader io.Reader) Result {
	return CopyBidirectionalContext(context.Background(), a, aReader, b, bReader)
}

// CopyBidirectionalContext preserves normal half-close/drain behavior until ctx
// is canceled. Cancellation force-closes BOTH transports and waits for workers;
// callers should supply a grace-expiry context rather than process cancellation.
func CopyBidirectionalContext(ctx context.Context, a net.Conn, aReader io.Reader, b net.Conn, bReader io.Reader) Result {
	return copyObserved(ctx, a, aReader, b, bReader, nil)
}

// CopyBidirectionalObservedContext emits at most one first-data observation in
// each direction, relative to relay entry. Prebuffered data is already available.
func CopyBidirectionalObservedContext(ctx context.Context, a net.Conn, aReader io.Reader, b net.Conn, bReader io.Reader, observe func(string, time.Duration)) Result {
	return copyObserved(ctx, a, aReader, b, bReader, observe)
}
func copyObserved(ctx context.Context, a net.Conn, aReader io.Reader, b net.Conn, bReader io.Reader, observe func(string, time.Duration)) Result {
	resultCh := make(chan copyResult, 2)

	started := time.Now()
	go copyDirectionObserved(resultCh, directionAToB, b, aReader, started, observe)
	go copyDirectionObserved(resultCh, directionBToA, a, bReader, started, observe)

	aborted := false
	var abortErr error
	waitResult := func() copyResult {
		if aborted {
			return <-resultCh
		}
		select {
		case copied := <-resultCh:
			return copied
		case <-ctx.Done():
			aborted = true
			abortErr = abortTransports(a, b)
			return <-resultCh
		}
	}
	first := waitResult()
	result := Result{}
	setDirectionResult(&result, first)

	var interruptErr error
	if first.result.Err != nil && !aborted {
		interruptErr = interrupt(a, b)
	}

	second := waitResult()
	setDirectionResult(&result, second)

	switch {
	case first.result.Err != nil:
		// The second direction was deliberately interrupted. Its detailed error
		// remains in Result, but the first failure is the relay's root cause.
		result.FailureDirection = directionName(first.direction)
		result.FailurePhase = first.result.Phase
		result.Fault = describeFault(first.result.Err, first.result.Phase, first.direction, a, b)
		result.Err = errors.Join(directionError(first), interruptErr)
	case second.result.Err != nil:
		result.FailureDirection = directionName(second.direction)
		result.FailurePhase = second.result.Phase
		result.Fault = describeFault(second.result.Err, second.result.Phase, second.direction, a, b)
		result.Err = directionError(second)
	}
	result.Err = errors.Join(result.Err, abortErr)

	return result
}

func abortTransports(conns ...net.Conn) error {
	var result error
	for _, conn := range conns {
		if conn == nil {
			continue
		}
		if wrapped, ok := conn.(interface{ NetConn() net.Conn }); ok {
			conn = wrapped.NetConn()
		}
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, fmt.Errorf("abort %T: %w", conn, err))
		}
	}
	return result
}

func copyDirection(resultCh chan<- copyResult, direction direction, dst net.Conn, src io.Reader) {
	copyDirectionObserved(resultCh, direction, dst, src, time.Now(), nil)
}
func copyDirectionObserved(resultCh chan<- copyResult, direction direction, dst net.Conn, src io.Reader, started time.Time, observe func(string, time.Duration)) {
	first := firstCopy{started: started}
	if observe != nil {
		first.notify = func(d time.Duration) { observe(directionName(direction), d) }
		src = firstReader{src, &first}
	}
	written, copyErr := io.Copy(dst, src)
	var shutdownErr error
	if copyErr == nil {
		shutdownErr = closeWrite(dst)
	}
	var phase string
	if copyErr != nil {
		phase = "copy"
	} else if shutdownErr != nil {
		phase = "half_close"
	}

	resultCh <- copyResult{
		direction: direction,
		result: DirectionResult{
			Bytes:         written,
			FirstByteSeen: first.seen, FirstByteDuration: first.elapsed,
			Phase: phase,
			Err: errors.Join(
				wrapError("copy stream", copyErr),
				wrapError("close write side", shutdownErr),
			),
		},
	}
}

func closeWrite(conn net.Conn) error {
	if conn == nil {
		return fmt.Errorf("%w: <nil>", ErrHalfCloseUnsupported)
	}

	cw, ok := conn.(closeWriter)
	if !ok {
		return fmt.Errorf("%w: %T", ErrHalfCloseUnsupported, conn)
	}

	return cw.CloseWrite()
}

func interrupt(conns ...net.Conn) error {
	now := time.Now()
	var result error

	for _, conn := range conns {
		if conn == nil {
			continue
		}

		if err := conn.SetDeadline(now); err != nil {
			result = errors.Join(result, fmt.Errorf("interrupt %T: %w", conn, err))
			if closeErr := conn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
				result = errors.Join(result, fmt.Errorf("close %T after interrupt failure: %w", conn, closeErr))
			}
		}
	}

	return result
}

func setDirectionResult(result *Result, copied copyResult) {
	if copied.direction == directionAToB {
		result.AToB = copied.result
		return
	}

	result.BToA = copied.result
}

func directionError(copied copyResult) error {
	if copied.result.Err == nil {
		return nil
	}

	if copied.direction == directionAToB {
		return fmt.Errorf("a to b: %w", copied.result.Err)
	}

	return fmt.Errorf("b to a: %w", copied.result.Err)
}

func wrapError(operation string, err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("%s: %w", operation, err)
}

func directionName(d direction) string {
	if d == directionAToB {
		return "up"
	}
	return "down"
}
