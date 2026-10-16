package tunnel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
)

func TestTargetErrorClassificationAndLegacyCompatibility(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
		rep  byte
	}{
		{context.DeadlineExceeded, "TIMEOUT", 4}, {&net.DNSError{Err: "not found", Name: "example.invalid", IsNotFound: true}, "DNS", 4},
		{syscall.ENETUNREACH, "NETWORK", 3}, {syscall.EHOSTUNREACH, "HOST", 4}, {syscall.ECONNREFUSED, "REFUSED", 5},
		{syscall.EMFILE, "LIMIT", 1}, {context.Canceled, "CANCELED", 1}, {errors.New("private detail"), "INTERNAL", 1},
	} {
		t.Run(tc.code, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			done := make(chan error, 1)
			go func() { done <- SendTargetError(a, fmt.Errorf("wrapped: %w", tc.err)) }()
			line, err := ReadLine(bufio.NewReader(b))
			if err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if line != "ERR "+tc.code || line == "OK" {
				t.Fatal("legacy client would not reject", line)
			}
			got := ParseConnectResponse(line)
			var target *TargetError
			if !errors.As(got, &target) || target.Code != tc.code || target.SOCKSReplyCode() != tc.rep || !errors.Is(got, ErrConnectRejected) {
				t.Fatal(got)
			}
		})
	}
	if !errors.Is(ParseConnectResponse("ERR"), ErrConnectRejected) || ParseConnectResponse("OK") != nil {
		t.Fatal("legacy replies broken")
	}
	for _, line := range []string{"ERR unknown", "ERR TIMEOUT detail", "BUSY", "ERR\nREFUSED"} {
		if !errors.Is(ParseConnectResponse(line), ErrConnectResponse) {
			t.Fatal("invalid reply accepted", line)
		}
	}
}
