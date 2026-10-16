package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadClientConfigSocksAuth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.json")
	data := `{"remote_addr":"server:8443","auth_token":"tunnel-token","socks_auth":{"username":"nested-user","password":"nested-pass"},"socks_username":"legacy-user","socks_password":"legacy-pass"}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadClientConfig(path)
	if err != nil {
		t.Fatalf("LoadClientConfig() error = %v", err)
	}
	username, password, enabled := cfg.SOCKSCredentials()
	if !enabled || username != "nested-user" || password != "nested-pass" {
		t.Fatalf("SOCKSCredentials() = (%q, %q, %v)", username, password, enabled)
	}
}

func TestLoadClientConfigSocksAuthLegacyFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.json")
	data := `{"remote_addr":"server:8443","auth_token":"tunnel-token","socks_username":"legacy-user","socks_password":"legacy-pass"}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadClientConfig(path)
	if err != nil {
		t.Fatalf("LoadClientConfig() error = %v", err)
	}
	username, password, enabled := cfg.SOCKSCredentials()
	if !enabled || username != "legacy-user" || password != "legacy-pass" {
		t.Fatalf("SOCKSCredentials() = (%q, %q, %v)", username, password, enabled)
	}
}
