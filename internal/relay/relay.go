package relay

import (
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
	Bytes int64
	Err   error
}

// Result contains transfer statistics for both directions and the error that
// caused the relay to stop. AToB is the upload direction at both current call
// sites, while BToA is the download direction.
type Result struct {
	AToB DirectionResult
	BToA DirectionResult
	Err  error
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
	resultCh := make(chan copyResult, 2)

	go copyDirection(resultCh, directionAToB, b, aReader)
	go copyDirection(resultCh, directionBToA, a, bReader)

	first := <-resultCh
	result := Result{}
	setDirectionResult(&result, first)

	var interruptErr error
	if first.result.Err != nil {
		interruptErr = interrupt(a, b)
	}

	second := <-resultCh
	setDirectionResult(&result, second)

	switch {
	case first.result.Err != nil:
		// The second direction was deliberately interrupted. Its detailed error
		// remains in Result, but the first failure is the relay's root cause.
		result.Err = errors.Join(directionError(first), interruptErr)
	case second.result.Err != nil:
		result.Err = directionError(second)
	}

	return result
}

func copyDirection(resultCh chan<- copyResult, direction direction, dst net.Conn, src io.Reader) {
	written, copyErr := io.Copy(dst, src)
	shutdownErr := closeWrite(dst)

	resultCh <- copyResult{
		direction: direction,
		result: DirectionResult{
			Bytes: written,
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
