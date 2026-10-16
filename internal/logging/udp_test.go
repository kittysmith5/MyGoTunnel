package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"mygotunnel/internal/datagram"
	"mygotunnel/internal/tunnel"
)

func TestUDPTerminationReasonRootAndProcessCounters(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		for _, tc := range []struct {
			stage  string
			err    error
			reason string
			failed bool
		}{
			{"udp_control", nil, "eof", false}, {"udp_tunnel_read", io.EOF, "eof", false},
			{"udp_tunnel_write", context.DeadlineExceeded, "timeout", true},
			{"udp_tunnel_read", io.ErrUnexpectedEOF, "truncated", true},
			{"udp_tunnel_read", syscall.ECONNRESET, "reset", true},
			{"udp_tunnel_read", net.ErrClosed, "closed", true},
			{"udp_tunnel_read", context.Canceled, "canceled", true},
			{"udp_tunnel_read", errors.New("synthetic failure"), "error", true},
		} {
			t.Run(format+"/"+tc.stage+"/"+tc.reason, func(t *testing.T) {
				var output bytes.Buffer
				logger, err := New(&output, Options{Component: "client", Format: format, Level: "info"})
				if err != nil {
					t.Fatal(err)
				}
				r := datagram.NewResources(1, 1024)
				defer r.Close()
				LogUDPResult(logger, r, tc.stage, tc.err, tunnel.DatagramWriteStats{Calls: 2, Errors: 1, Timeouts: 1, MaxDuration: 1234 * time.Microsecond}, "upload_datagrams", 3)
				wantErrors := uint64(0)
				if tc.failed {
					wantErrors = 1
				}
				s := r.Stats()
				if s.Sessions != 1 || s.SessionErrors != wantErrors {
					t.Fatal(s)
				}
				if tc.stage == "udp_tunnel_write" && s.WriteTimeouts != 1 {
					t.Fatal(s)
				}
				ends := s.Terminations
				if ends.EOF+ends.Timeout+ends.Reset+ends.Truncated+ends.Canceled+ends.Closed+ends.Other != 1 {
					t.Fatal("termination causes overlap", s)
				}
				if tc.stage != "udp_tunnel_write" && s.WriteErrors != 0 {
					t.Fatal("secondary write changed root counters", s)
				}
				if format == "text" {
					if !strings.Contains(output.String(), "stage="+tc.stage+" reason="+tc.reason) || !strings.Contains(output.String(), "udp_tunnel_write_max_duration=1.234ms") {
						t.Fatal(output.String())
					}
				} else {
					var row map[string]any
					if err := json.Unmarshal(output.Bytes(), &row); err != nil {
						t.Fatal(err)
					}
					if row["stage"] != tc.stage || row["close_reason"] != tc.reason || row["udp_tunnel_write_max_duration"] != float64(1234000) {
						t.Fatal(row)
					}
				}
			})
		}
	}
}

func TestTypedTargetReasonsPrecedeGenericRejection(t *testing.T) {
	for _, tc := range []struct{ code, reason string }{{"TIMEOUT", "timeout"}, {"DNS", "dns"}, {"NETWORK", "unreachable"}, {"REFUSED", "refused"}, {"LIMIT", "limit"}} {
		err := &tunnel.TargetError{Code: tc.code}
		if !errors.Is(err, tunnel.ErrConnectRejected) || Reason(err) != tc.reason {
			t.Fatal(tc, Reason(err))
		}
	}
	if Reason(tunnel.ErrConnectResponse) != "protocol" || Reason(datagram.ErrResourceLimit) != "limit" {
		t.Fatal("new classifications missing")
	}
}
