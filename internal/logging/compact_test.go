package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"mygotunnel/internal/relay"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestCompactTimestampFieldsAndDirection(t *testing.T) {
	var out bytes.Buffer
	h := newCompactHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug}).WithAttrs([]slog.Attr{slog.String("component", "client"), slog.String("connection_id", "test-1")})
	when := time.Date(2026, 10, 13, 23, 23, 12, 57000000, time.FixedZone("CST", 8*3600))
	record := slog.NewRecord(when, slog.LevelInfo, "closed", 0)
	record.Add("target_addr", "example.test:443", "client_addr", "127.0.0.1:1234", "upload_bytes", int64(1024), "download_bytes", int64(2048), "duration", 105*time.Millisecond, "close_reason", "eof")
	if err := h.Handle(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	want := "2026-10-13 15:23:12.057 INFO C closed example.test:443 id=test-1 peer=127.0.0.1:1234 ↑1.0KiB ↓2.0KiB dur=105ms reason=eof\n"
	if out.String() != want {
		t.Fatalf("got %q want %q", out.String(), want)
	}
	for _, forbidden := range []string{"level=", "msg=", "component=", "target_addr="} {
		if strings.Contains(out.String(), forbidden) {
			t.Fatal("verbose envelope retained")
		}
	}
}
func TestCompactPoolAndStats(t *testing.T) {
	var out bytes.Buffer
	logger, err := New(&out, Options{Component: "client"})
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("ready", "pool_hit", true, "pool_fallback", false, "tcp_duration", time.Duration(0), "tls_duration", time.Duration(0), "pool_acquire_duration", 100*time.Microsecond, "control_duration", 105*time.Millisecond)
	got := out.String()
	if !strings.Contains(got, "pool=hit take=0.1ms ctl=105ms") || strings.Contains(got, "tcp=") || strings.Contains(got, "tls=") {
		t.Fatal(got)
	}
	out.Reset()
	logger.Warn("failed", "stage", "dial", "close_reason", "dns_timeout", "dns_retry_count", 1)
	if !strings.Contains(out.String(), "reason=dns_timeout dns_retry=1") {
		t.Fatal(out.String())
	}
	out.Reset()
	logger.Info("ready", "pool_hit", false, "pool_fallback", true)
	if !strings.Contains(out.String(), "pool=fallback") {
		t.Fatal(out.String())
	}
	out.Reset()
	logger.Info("stats", "active_connections", int64(12), "max_connections", 1024, "setup_connections", int64(3), "max_setup", 128, "idle_connections", 4, "max_idle", 4, "rejected", int64(2))
	if !strings.Contains(out.String(), "stats active=12/1024 setup=3/128 idle=4/4 rejected=2") {
		t.Fatal(out.String())
	}
}
func TestCompactGroupsConcurrentWritesAndEscaping(t *testing.T) {
	var out bytes.Buffer
	logger, err := New(&out, Options{Component: "server"})
	if err != nil {
		t.Fatal(err)
	}
	grouped := logger.WithGroup("net").With("peer", "line\nbreak")
	grouped.Info("safe", "value", "with space")
	if strings.Count(out.String(), "\n") != 1 || !strings.Contains(out.String(), `net.peer="line\nbreak"`) {
		t.Fatal("log injection or group lost")
	}
	out.Reset()
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); logger.With("connection_id", fmt.Sprint(i)).Info("ready") }(i)
	}
	wg.Wait()
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 40 {
		t.Fatal("concurrent records interleaved")
	}
	for _, line := range lines {
		if !strings.Contains(line, " INFO S ready id=") {
			t.Fatal(line)
		}
	}
}
func TestKnownErrorsKeepDetailOnlyInDebug(t *testing.T) {
	for _, level := range []string{"info", "debug"} {
		var out bytes.Buffer
		logger, err := New(&out, Options{Component: "client", Level: level, Format: FormatJSON})
		if err != nil {
			t.Fatal(err)
		}
		failure := fmt.Errorf("copy stream: %w", &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET})
		LogTunnelResult(logger, relay.Result{AToB: relay.DirectionResult{Bytes: 12}, Err: failure, FailureDirection: "up"}, time.Now())
		lines := strings.Split(strings.TrimSpace(out.String()), "\n")
		var entry map[string]any
		json.Unmarshal([]byte(lines[0]), &entry)
		if entry["stage"] != "up" || entry["close_reason"] != "reset" || entry["upload_bytes"] != float64(12) {
			t.Fatal(entry)
		}
		if _, ok := entry["error"]; ok {
			t.Fatal("recognized error detail leaked into ordinary log")
		}
		if level == "debug" {
			if len(lines) != 2 || !strings.Contains(lines[1], "copy stream") {
				t.Fatal("debug detail missing")
			}
		} else if len(lines) != 1 {
			t.Fatal("unexpected debug record")
		}
	}
}
func TestConnectionIDsAndStatsStop(t *testing.T) {
	var out bytes.Buffer
	logger, err := New(&out, Options{Component: "client", Format: FormatJSON})
	if err != nil {
		t.Fatal(err)
	}
	first := Connection(logger, "127.0.0.1:1")
	first.Info("ready")
	first.Info("closed")
	Connection(logger, "127.0.0.1:2").Info("ready")
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var ids []string
	for _, line := range lines {
		var e map[string]any
		json.Unmarshal([]byte(line), &e)
		ids = append(ids, e["connection_id"].(string))
	}
	if ids[0] != ids[1] || ids[1] == ids[2] {
		t.Fatal("connection IDs inconsistent")
	}
	out.Reset()
	seen := make(chan struct{})
	var once sync.Once
	stop := StartStats(logger, time.Millisecond, func() []any { once.Do(func() { close(seen) }); return []any{"active_connections", 0} })
	select {
	case <-seen:
	case <-time.After(time.Second):
		t.Fatal("stats timer did not fire")
	}
	stop()
	stop()
	before := out.Len()
	time.Sleep(5 * time.Millisecond)
	if before == 0 || out.Len() != before {
		t.Fatal("stats missing or continued after stop")
	}
}

func TestSOCKSStageFieldNamesAndJSONUnits(t *testing.T) {
	for _, format := range []string{FormatText, FormatJSON} {
		var out bytes.Buffer
		logger, err := New(&out, Options{Component: "client", Format: format})
		if err != nil {
			t.Fatal(err)
		}
		logger.Info("ready", "socks_first_byte_duration", time.Millisecond, "socks_method_duration", 2*time.Millisecond, "socks_auth_duration", 3*time.Millisecond, "socks_request_duration", 4*time.Millisecond)
		if format == FormatText {
			if !strings.Contains(out.String(), "sfirst=1ms smethod=2ms sauth=3ms sreq=4ms") {
				t.Fatal(out.String())
			}
		} else {
			var entry map[string]any
			if err := json.Unmarshal(out.Bytes(), &entry); err != nil {
				t.Fatal(err)
			}
			for i, key := range []string{"socks_first_byte_duration", "socks_method_duration", "socks_auth_duration", "socks_request_duration"} {
				if entry[key] != float64(time.Duration(i+1)*time.Millisecond) {
					t.Fatal(entry)
				}
			}
		}
	}
}
