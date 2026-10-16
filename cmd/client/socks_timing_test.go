package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"mygotunnel/internal/config"
)

func TestSOCKSStageLoggingOnRequestFailure(t *testing.T) {
	var out bytes.Buffer
	a, b := net.Pipe()
	defer b.Close()
	b.SetDeadline(time.Now().Add(time.Second))
	done := make(chan struct{})
	go func() {
		handleClient(a, &config.ClientConfig{SOCKSAuth: &config.SOCKSAuth{Username: "private-user", Password: "private-pass"}}, slog.New(slog.NewJSONHandler(&out, nil)), func() {})
		close(done)
	}()
	if _, err := b.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(b, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	auth := append([]byte{1, 12}, []byte("private-user")...)
	auth = append(auth, 12)
	auth = append(auth, []byte("private-pass")...)
	if _, err := b.Write(auth); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(b, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := b.Write([]byte{5, 2, 0, 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(b, make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler leaked")
	}
	if strings.Contains(out.String(), "private-user") || strings.Contains(out.String(), "private-pass") {
		t.Fatal("credentials leaked")
	}
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &entry); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"socks_first_byte_duration", "socks_method_duration", "socks_auth_duration", "socks_request_duration"} {
		if _, ok := entry[key].(float64); !ok {
			t.Fatalf("missing numeric %s: %v", key, entry)
		}
	}
	if entry["socks_request_duration"].(float64) < float64(10*time.Millisecond) {
		t.Fatal("request wait missing", entry)
	}
	if entry["stage"] != "socks" {
		t.Fatal("failure stage changed", entry)
	}
}
