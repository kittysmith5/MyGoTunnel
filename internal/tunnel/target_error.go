package tunnel

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
)

type TargetError struct{ Code string }

var ErrConnectResponse = errors.New("invalid connection response")

func (e *TargetError) Error() string     { return "target connection failed: " + e.Code }
func (e *TargetError) Is(err error) bool { return err == ErrConnectRejected }
func (e *TargetError) SOCKSReplyCode() byte {
	switch e.Code {
	case "TIMEOUT", "DNS", "HOST":
		return 4
	case "NETWORK":
		return 3
	case "REFUSED":
		return 5
	default:
		return 1
	}
}
func (e *TargetError) Reason() string {
	switch e.Code {
	case "TIMEOUT":
		return "timeout"
	case "DNS":
		return "dns"
	case "NETWORK", "HOST":
		return "unreachable"
	case "REFUSED":
		return "refused"
	case "LIMIT":
		return "limit"
	case "CANCELED":
		return "canceled"
	default:
		return "error"
	}
}

func ClassifyTargetError(err error) *TargetError {
	code := "INTERNAL"
	var dns *net.DNSError
	var network net.Error
	switch {
	case errors.As(err, &dns):
		code = "DNS"
	case errors.Is(err, context.Canceled):
		code = "CANCELED"
	case errors.Is(err, context.DeadlineExceeded):
		code = "TIMEOUT"
	case errors.As(err, &network) && network.Timeout():
		code = "TIMEOUT"
	case errors.Is(err, syscall.ECONNREFUSED):
		code = "REFUSED"
	case errors.Is(err, syscall.ENETUNREACH):
		code = "NETWORK"
	case errors.Is(err, syscall.EHOSTUNREACH):
		code = "HOST"
	case errors.Is(err, syscall.EMFILE), errors.Is(err, syscall.ENFILE), errors.Is(err, syscall.ENOBUFS), errors.Is(err, syscall.ENOMEM):
		code = "LIMIT"
	}
	return &TargetError{Code: code}
}

func validTargetCode(code string) bool {
	switch code {
	case "TIMEOUT", "DNS", "NETWORK", "HOST", "REFUSED", "LIMIT", "CANCELED", "INTERNAL":
		return true
	}
	return false
}

// Legacy clients already treat every non-OK reply as rejection. New clients
// accept legacy ERR and only interpret a fixed allowlist of machine codes.
func SendTargetError(conn net.Conn, err error) error {
	return writeControl(conn, "ERR "+ClassifyTargetError(err).Code+"\n")
}

func ParseConnectResponse(line string) error {
	if line == "OK" {
		return nil
	}
	if line == "ERR" {
		return ErrConnectRejected
	}
	if code, ok := strings.CutPrefix(line, "ERR "); ok && validTargetCode(code) {
		return &TargetError{Code: code}
	}
	return ErrConnectResponse
}
