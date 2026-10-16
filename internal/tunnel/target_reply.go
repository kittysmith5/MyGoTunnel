package tunnel

import (
	"fmt"
	"net"
	"time"
)

// SendTargetResult reserves a short write budget even when the preceding
// control read/dial deadline has expired. Success callers clear all deadlines
// before relay; failure callers close the connection after the reply.
func SendTargetResult(conn net.Conn, cause error) error {
	if err := conn.SetWriteDeadline(time.Now().Add(ControlReplyTimeout)); err != nil {
		return fmt.Errorf("set target reply deadline: %w", err)
	}
	if cause != nil {
		return SendTargetError(conn, cause)
	}
	return writeControl(conn, "OK\n")
}
