package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"mygotunnel/internal/relay"
)

func TestNewRejectsInvalidOptions(t *testing.T) {
	tests := []struct {
		name    string
		writer  io.Writer
		options Options
	}{
		{
			name:   "nil writer",
			writer: nil,
			options: Options{
				Component: "client",
			},
		},
		{
			name:   "empty component",
			writer: io.Discard,
			options: Options{
				Component: " ",
			},
		},
		{
			name:   "invalid level",
			writer: io.Discard,
			options: Options{
				Component: "client",
				Level:     "verbose",
			},
		},
		{
			name:   "invalid format",
			writer: io.Discard,
			options: Options{
				Component: "client",
				Format:    "xml",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.writer, tt.options); err == nil {
				t.Fatal("New() error = nil, want an error")
			}
		})
	}
}

func TestNewJSONLogger(t *testing.T) {
	var output bytes.Buffer

	logger, err := New(&output, Options{
		Component: "client",
		Level:     "debug",
		Format:    "JSON",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	logger.Debug("connection accepted", "client_addr", "127.0.0.1:1234")

	var entry map[string]any
	if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
		t.Fatalf("decode log entry: %v", err)
	}

	if got := entry["level"]; got != "DEBUG" {
		t.Errorf("level = %v, want DEBUG", got)
	}
	if got := entry["msg"]; got != "connection accepted" {
		t.Errorf("msg = %v, want connection accepted", got)
	}
	if got := entry["component"]; got != "client" {
		t.Errorf("component = %v, want client", got)
	}
	if got := entry["client_addr"]; got != "127.0.0.1:1234" {
		t.Errorf("client_addr = %v, want 127.0.0.1:1234", got)
	}
}

func TestNewDefaultsToInfoTextLogger(t *testing.T) {
	var output bytes.Buffer

	logger, err := New(&output, Options{Component: "server"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	logger.Debug("hidden")
	logger.Info("listener started", "listen_addr", ":9001")

	got := output.String()
	if strings.Contains(got, "hidden") {
		t.Errorf("debug log was not filtered: %q", got)
	}
	for _, want := range []string{"level=INFO", `msg="listener started"`, "component=server", "listen_addr=:9001"} {
		if !strings.Contains(got, want) {
			t.Errorf("log output %q does not contain %q", got, want)
		}
	}
}

func TestLogTunnelResult(t *testing.T) {
	tests := []struct {
		name      string
		result    relay.Result
		wantLevel string
		wantMsg   string
	}{
		{
			name: "clean close",
			result: relay.Result{
				AToB: relay.DirectionResult{Bytes: 12},
				BToA: relay.DirectionResult{Bytes: 34},
			},
			wantLevel: "INFO",
			wantMsg:   "tunnel closed",
		},
		{
			name: "relay failure",
			result: relay.Result{
				AToB: relay.DirectionResult{Bytes: 12},
				BToA: relay.DirectionResult{Bytes: 34},
				Err:  errors.New("copy failed"),
			},
			wantLevel: "WARN",
			wantMsg:   "tunnel relay failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			logger, err := New(&output, Options{Component: "client", Format: FormatJSON})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			LogTunnelResult(logger, tt.result, time.Now())

			var entry map[string]any
			if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
				t.Fatalf("decode log entry: %v", err)
			}

			if got := entry["level"]; got != tt.wantLevel {
				t.Errorf("level = %v, want %s", got, tt.wantLevel)
			}
			if got := entry["msg"]; got != tt.wantMsg {
				t.Errorf("msg = %v, want %s", got, tt.wantMsg)
			}
			if got := entry["upload_bytes"]; got != float64(12) {
				t.Errorf("upload_bytes = %v, want 12", got)
			}
			if got := entry["download_bytes"]; got != float64(34) {
				t.Errorf("download_bytes = %v, want 34", got)
			}
		})
	}
}
