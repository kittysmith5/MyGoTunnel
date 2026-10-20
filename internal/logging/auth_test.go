package logging

import (
	"context"
	"errors"
	"io"
	"testing"

	"mygotunnel/internal/socks5"
)

func TestSOCKSAuthenticationFailureReasons(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"mismatch", socks5.ErrAuthRejected, "auth_rejected"},
		{"limited", socks5.ErrAuthLimited, "auth_limited"},
		{"protocol", socks5.ErrAuthProtocol, "auth_protocol"},
		{"rejected reply failed", errors.Join(socks5.ErrAuthRejected, io.ErrClosedPipe), "auth_rejected"},
		{"limited reply timed out", errors.Join(socks5.ErrAuthLimited, context.DeadlineExceeded), "auth_limited"},
		{"truncated auth", io.ErrUnexpectedEOF, "truncated"},
		{"auth read timed out", context.DeadlineExceeded, "timeout"},
		{"other SOCKS request error", errors.New("invalid request"), "error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Reason(tc.err); got != tc.want {
				t.Fatalf("reason=%s want %s", got, tc.want)
			}
		})
	}
}
