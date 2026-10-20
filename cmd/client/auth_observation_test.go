package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"mygotunnel/internal/authlimit"
	"mygotunnel/internal/config"
	"mygotunnel/internal/datagram"
)

// Python's observer consumes this same contract fixture. These events are
// checked against real client handshakes, so observation tests cannot invent
// authentication stages or reasons that the application never emits.
func TestSOCKSAuthenticationLogObservationContract(t *testing.T) {
	fixture, err := os.Open("../../internal/logging/testdata/socks_auth_events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()
	scanner := bufio.NewScanner(fixture)
	for scanner.Scan() {
		var expected map[string]string
		if err := json.Unmarshal(scanner.Bytes(), &expected); err != nil {
			t.Fatal(err)
		}
		t.Run(expected["connection_id"], func(t *testing.T) {
			var logs bytes.Buffer
			cfg := &config.ClientConfig{RemoteAddr: "127.0.0.1:1", AuthToken: "test-token", SOCKSAuth: &config.SOCKSAuth{Username: "u", Password: "p"}}
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			limiter := authlimit.New(8, 1, time.Minute, time.Minute)
			if expected["connection_id"] == "limited" {
				limiter.Failure(authlimit.PeerKey(server.RemoteAddr()))
			}
			resources := datagram.NewResources(8, 1<<20)
			defer resources.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				handleClientWithResourcesAndAuthLimiter(context.Background(), server, cfg, slog.New(slog.NewJSONHandler(&logs, nil)), func() {}, nil, resources, limiter)
			}()
			greeting := []byte{5, 1, 2}
			if expected["connection_id"] == "auth-method" {
				greeting[2] = 0
			}
			if _, err := client.Write(greeting); err != nil {
				t.Fatal(err)
			}
			var response [2]byte
			wantedMethod := [2]byte{5, 2}
			if expected["connection_id"] == "auth-method" {
				wantedMethod[1] = 255
			}
			if _, err := io.ReadFull(client, response[:]); err != nil || response != wantedMethod {
				t.Fatalf("method=%v error=%v", response, err)
			}
			if expected["connection_id"] != "auth-method" {
				payload := []byte{1, 1, 'u', 1, 'p'}
				switch expected["connection_id"] {
				case "mismatch":
					payload[len(payload)-1] = 'x'
				case "auth-protocol":
					payload = []byte{2, 1}
				}
				if _, err := client.Write(payload); err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadFull(client, response[:]); err != nil {
					t.Fatal(err)
				}
				if expected["connection_id"] == "request-protocol" {
					if response != [2]byte{1, 0} {
						t.Fatalf("valid authentication rejected: %v", response)
					}
					if _, err := client.Write([]byte{5, 1, 1, 1}); err != nil {
						t.Fatal(err)
					}
					var reply [10]byte
					if _, err := io.ReadFull(client, reply[:]); err != nil || reply[1] != 1 {
						t.Fatalf("request reply=%v error=%v", reply, err)
					}
				} else if response != [2]byte{1, 1} {
					t.Fatalf("invalid authentication accepted: %v", response)
				}
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("client handler did not exit")
			}
			var actual map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &actual); err != nil {
				t.Fatalf("log=%s error=%v", logs.String(), err)
			}
			if id, ok := actual["connection_id"].(string); !ok || id == "" {
				t.Fatal("missing connection ID")
			}
			for _, field := range []string{"msg", "stage", "close_reason"} {
				if actual[field] != expected[field] {
					t.Fatalf("%s=%v want %s; log=%s", field, actual[field], expected[field], logs.String())
				}
			}
		})
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}
