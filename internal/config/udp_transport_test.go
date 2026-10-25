package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeUDPTransportConfig(t *testing.T, role string, fields map[string]any) string {
	t.Helper()
	data, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), role+".json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestClientUDPTransportConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, mode, remote, wantMode, wantRemote string
		valid                                    bool
	}{
		{"default", "", "", "tcp", "server.invalid:8443", true},
		{"explicit tcp", "tcp", "", "tcp", "server.invalid:8443", true},
		{"quic same endpoint", "quic", "", "quic", "server.invalid:8443", true},
		{"quic independent endpoint", "quic", "udp.invalid:443", "quic", "udp.invalid:443", true},
		{"quic IPv6", "quic", "[::1]:443", "quic", "[::1]:443", true},
		{"quic scoped IPv6", "quic", "[fe80::1%test-interface]:443", "quic", "[fe80::1%test-interface]:443", true},
		{"stored endpoint with tcp", "tcp", "udp.invalid:8443", "tcp", "udp.invalid:8443", true},
		{"unknown mode", "auto", "", "", "", false},
		{"case sensitive mode", "QUIC", "", "", "", false},
		{"whitespace mode", "quic ", "", "", "", false},
		{"remote missing host", "quic", ":8443", "", "", false},
		{"remote zero port", "quic", "udp.invalid:0", "", "", false},
		{"remote oversized port", "quic", "udp.invalid:65536", "", "", false},
		{"remote named port", "quic", "udp.invalid:https", "", "", false},
		{"remote signed port", "quic", "udp.invalid:+443", "", "", false},
		{"remote invalid host", "quic", "bad host:8443", "", "", false},
		{"remote invalid IPv6", "quic", "[not:ipv6]:8443", "", "", false},
		{"invalid dormant remote", "tcp", "udp.invalid:0", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeUDPTransportConfig(t, "client", map[string]any{
				"remote_addr": "server.invalid:8443", "auth_token": "test-token",
				"udp_transport": tc.mode, "udp_quic_remote_addr": tc.remote,
			})
			cfg, err := LoadClientConfig(path)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
			if err == nil && (cfg.UDPTransportMode() != tc.wantMode || cfg.UDPQUICRemote() != tc.wantRemote || cfg.RemoteAddr != "server.invalid:8443") {
				t.Fatalf("transport=%q endpoint=%q tcp endpoint=%q", cfg.UDPTransportMode(), cfg.UDPQUICRemote(), cfg.RemoteAddr)
			}
		})
	}
}

func TestServerUDPQUICListenerConfiguration(t *testing.T) {
	for _, tc := range []struct {
		address string
		valid   bool
	}{
		{"", true}, {":8443", true}, {"127.0.0.1:0", true}, {"[::]:443", true},
		{"server.invalid:8443", true}, {"[fe80::1%test-interface]:8443", true},
		{"8443", false}, {":65536", false}, {":-1", false}, {":+443", false},
		{":https", false}, {"bad host:8443", false}, {"[not:ipv6]:8443", false},
	} {
		t.Run(tc.address, func(t *testing.T) {
			path := writeUDPTransportConfig(t, "server", map[string]any{
				"auth_token": "test-token", "udp_quic_listen_addr": tc.address,
			})
			cfg, err := LoadServerConfig(path)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
			if err == nil && (cfg.UDPQUICListenAddr != tc.address || cfg.ListenAddr != ":9001") {
				t.Fatalf("unexpected listener configuration: TCP=%q QUIC=%q", cfg.ListenAddr, cfg.UDPQUICListenAddr)
			}
		})
	}
}

func TestConnectionCodeDoesNotExportUDPTransportPolicy(t *testing.T) {
	for _, mode := range []string{"ca", "pin"} {
		t.Run(mode, func(t *testing.T) {
			cfg := &ClientConfig{
				RemoteAddr: "server.invalid:8443", AuthToken: "test-token", TrustMode: mode,
				UDPTransport: "quic", UDPQUICRemoteAddr: "udp.invalid:443",
			}
			if mode == "pin" {
				cfg.CertificateFingerprint = strings.Repeat("ab", 32)
			}
			code, err := EncodeConnection(cfg)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeConnection(code)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.UDPTransport != "" || decoded.UDPQUICRemoteAddr != "" || decoded.UDPTransportMode() != "tcp" || decoded.UDPQUICRemote() != cfg.RemoteAddr {
				t.Fatal("connection code exported local UDP transport policy")
			}
			path := filepath.Join(t.TempDir(), "imported.json")
			if err := ImportClient(strings.NewReader(code), path); err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadClientConfig(path)
			if err != nil || loaded.UDPTransportMode() != "tcp" || loaded.UDPQUICRemoteAddr != "" {
				t.Fatalf("imported transport policy: %v", err)
			}
		})
	}
}
