package logging

import (
	"bytes"
	"encoding/json"
	"syscall"
	"testing"
	"time"

	"mygotunnel/internal/relay"
)

func TestHalfCloseFailureIsDistinguishedFromCopyFailure(t *testing.T) {
	var out bytes.Buffer
	logger, err := New(&out, Options{Component: "client", Format: FormatJSON})
	if err != nil {
		t.Fatal(err)
	}
	LogTunnelResult(logger, relay.Result{Err: syscall.ENOTCONN, FailureDirection: "down", FailurePhase: "half_close"}, time.Now())
	var record map[string]any
	if err := json.Unmarshal(out.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record["failure_phase"] != "half_close" || record["close_reason"] != "closed" || record["stage"] != "down" || record["msg"] != "failed" {
		t.Fatal(record)
	}
}
