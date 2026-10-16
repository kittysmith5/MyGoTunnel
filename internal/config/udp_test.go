package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"mygotunnel/internal/datagram"
)

func TestUDPQueueConfigDefaultsOverridesAndValidation(t *testing.T) {
	for _, tc := range []struct {
		bytes, age int
		valid      bool
	}{
		{0, 0, true}, {65000, 1, true}, {2 * 1024 * 1024, 1000, true}, {64 * 1024 * 1024, 60000, true},
		{-1, 0, false}, {64999, 0, false}, {64*1024*1024 + 1, 0, false}, {0, -1, false}, {0, 60001, false},
	} {
		for _, side := range []string{"client", "server"} {
			t.Run(fmt.Sprintf("%s/%d/%d", side, tc.bytes, tc.age), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "config.json")
				data := fmt.Sprintf(`{"auth_token":"test-token","remote_addr":"example.test:443","udp_queue_max_bytes":%d,"udp_queue_max_age_ms":%d}`, tc.bytes, tc.age)
				if err := os.WriteFile(path, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
				var got UDPQueueConfig
				var err error
				if side == "client" {
					var cfg *ClientConfig
					cfg, err = LoadClientConfig(path)
					if cfg != nil {
						got = cfg.UDPQueueConfig
					}
				} else {
					var cfg *ServerConfig
					cfg, err = LoadServerConfig(path)
					if cfg != nil {
						got = cfg.UDPQueueConfig
					}
				}
				if (err == nil) != tc.valid {
					t.Fatalf("validation: %v", err)
				}
				if !tc.valid {
					return
				}
				bytes, age := got.QueueLimits()
				wantBytes, wantAge := tc.bytes, time.Duration(tc.age)*time.Millisecond
				if wantBytes == 0 {
					wantBytes = datagram.DefaultMaxBytes
				}
				if wantAge == 0 {
					wantAge = datagram.DefaultMaxAge
				}
				if bytes != wantBytes || age != wantAge {
					t.Fatalf("limits %d %v", bytes, age)
				}
			})
		}
	}
}
