package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"syscall"
	"testing"
	"time"

	"mygotunnel/internal/relay"
)

func TestRelayFaultBothFormatsAndEndpointRoles(t *testing.T) {
	for _, format := range []string{FormatText, FormatJSON} {
		for _, roles := range [][]string{{"application", "tunnel"}, {"tunnel", "target"}} {
			var out bytes.Buffer
			logger, _ := New(&out, Options{Component: "client", Format: format})
			r := relay.Result{Err: syscall.ECONNRESET, FailureDirection: "down", FailurePhase: "copy",
				Fault: relay.Fault{Endpoint: "b", Operation: "read", Errno: uint64(syscall.ECONNRESET), LocalAddr: "127.0.0.1:1", RemoteAddr: "127.0.0.1:2"}}
			LogTunnelResult(logger, r, time.Now(), roles...)
			if format == FormatJSON {
				var row map[string]any
				if err := json.Unmarshal(out.Bytes(), &row); err != nil {
					t.Fatal(err)
				}
				if row["error_operation"] != "read" || row["error_endpoint"] != roles[1] || row["error_errno"] != float64(syscall.ECONNRESET) || row["error_remote_addr"] != "127.0.0.1:2" || row["level"] != "WARN" {
					t.Fatal(row)
				}
			} else if !strings.Contains(out.String(), "op=read endpoint="+roles[1]) || !strings.Contains(out.String(), "error_remote=127.0.0.1:2") {
				t.Fatal(out.String())
			}
		}
	}
}
