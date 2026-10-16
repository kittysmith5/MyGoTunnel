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

func TestUDPProcessAndWritePolicyValidation(t *testing.T) {
	for _, tc := range []struct {
		fields string
		valid  bool
	}{
		{``, true},
		{`,"udp_write_timeout_ms":20,"udp_max_sockets":2,"udp_memory_limit_bytes":262144`, true},
		{`,"udp_write_timeout_ms":600000,"udp_max_sockets":65536,"udp_memory_limit_bytes":1073741824`, true},
		{`,"udp_write_timeout_ms":-1`, false}, {`,"udp_write_timeout_ms":600001`, false},
		{`,"udp_max_sockets":-1`, false}, {`,"udp_max_sockets":65537`, false},
		{`,"udp_memory_limit_bytes":262143`, false}, {`,"udp_memory_limit_bytes":1073741825`, false},
	} {
		for _, side := range []string{"client", "server"} {
			t.Run(side+tc.fields, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "config.json")
				data := `{"auth_token":"test","remote_addr":"example.test:443"` + tc.fields + `}`
				if err := os.WriteFile(path, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
				var c UDPQueueConfig
				var err error
				if side == "client" {
					cfg, e := LoadClientConfig(path)
					err = e
					if cfg != nil {
						c = cfg.UDPQueueConfig
					}
				} else {
					cfg, e := LoadServerConfig(path)
					err = e
					if cfg != nil {
						c = cfg.UDPQueueConfig
					}
				}
				if (err == nil) != tc.valid {
					t.Fatal(err)
				}
				if !tc.valid {
					return
				}
				sockets, bytes := c.ProcessLimits()
				if tc.fields == "" {
					if c.WriteTimeout() != 5*time.Second || sockets != datagram.DefaultMaxSockets || bytes != datagram.DefaultMemoryLimit {
						t.Fatal(c)
					}
				} else if c.WriteTimeout() == 0 || sockets == 0 || bytes == 0 {
					t.Fatal(c)
				}
			})
		}
	}
}
