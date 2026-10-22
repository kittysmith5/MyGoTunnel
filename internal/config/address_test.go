package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestListenerAddressValidationIsOfflineAndKeepsPortZero(t *testing.T) {
	for _, tc := range []struct {
		address string
		valid   bool
	}{
		{":0", true}, {"127.0.0.1:0", true}, {"[::]:0", true}, {"[::1]:65535", true},
		{"localhost:1080", true}, {"[fe80::1%test-interface]:1080", true},
		{"127.0.0.1:70000", false}, {":65536", false}, {":-1", false}, {":+80", false},
		{":", false}, {":http", false}, {"localhost", false}, {"::1:1080", false},
		{"[not:ipv6]:1080", false}, {"bad host:1080", false}, {"bad/host:1080", false},
		{"host%scope:1080", false}, {"host\n:1080", false},
	} {
		t.Run(tc.address, func(t *testing.T) {
			for _, role := range []string{"client", "server"} {
				cfg := map[string]any{"auth_token": "test-token"}
				if role == "client" {
					cfg["remote_addr"] = "server.invalid:8443"
					cfg["local_addr"] = tc.address
				} else {
					cfg["listen_addr"] = tc.address
				}
				data, err := json.Marshal(cfg)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), role+".json")
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				if role == "client" {
					_, err = LoadClientConfig(path)
				} else {
					_, err = LoadServerConfig(path)
				}
				if (err == nil) != tc.valid {
					t.Fatalf("role=%s valid=%v error=%v", role, tc.valid, err)
				}
			}
		})
	}
}

func TestRemoteAddressStillRequiresNonzeroPortAndExplicitHost(t *testing.T) {
	for _, address := range []string{":8443", "host:0", "host:+80", "host:70000", "[not:ipv6]:443"} {
		if err := validateAddress(address); err == nil {
			t.Fatalf("accepted invalid remote endpoint %q", address)
		}
	}
	for _, address := range []string{"host.invalid:8443", "[::1]:443", "[fe80::1%test-interface]:443"} {
		if err := validateAddress(address); err != nil {
			t.Fatalf("valid remote endpoint %q rejected: %v", address, err)
		}
	}
}

func TestInitializeServerRejectsMalformedListenerWithoutCreatingCredentials(t *testing.T) {
	for _, address := range []string{"127.0.0.1:70000", "[not:ipv6]:9001", "bad host:9001", ":0"} {
		t.Run(address, func(t *testing.T) {
			directory := t.TempDir()
			if _, err := InitializeServer(filepath.Join(directory, "server.json"), "server.invalid:8443", address); err == nil {
				t.Fatal("invalid initializer listener accepted")
			}
			files, err := os.ReadDir(directory)
			if err != nil || len(files) != 0 {
				t.Fatalf("invalid initialization left credential files: count=%d error=%v", len(files), err)
			}
		})
	}
}
