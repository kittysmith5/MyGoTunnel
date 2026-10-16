package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestPreviousSOCKSCredentialExpires(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.json")
	data := `{"remote_addr":"localhost:8443","auth_token":"t","socks_auth":{"username":"new","password":"new-pass"},"previous_socks_auth":[{"username":"old","password":"old-pass","expires_at":"2099-01-01T00:00:00Z"}]}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadClientConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	live, _ := cfg.SOCKSCredentialSet(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if len(live) != 2 || live[1].Username != "old" {
		t.Fatalf("live=%+v", live)
	}
	expired, _ := cfg.SOCKSCredentialSet(time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC))
	if len(expired) != 1 {
		t.Fatalf("expired=%+v", expired)
	}
}

func TestLoadServerPreviousTokenValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")
	good := `{"auth_token":"new-token","previous_auth_tokens":[{"token":"old-token","expires_at":"2099-01-01T00:00:00Z"}]}`
	if err := os.WriteFile(path, []byte(good), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadServerConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ActiveAuthTokens(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); len(got) != 2 || got[1] != "old-token" {
		t.Fatalf("active=%v", got)
	}
	if got := cfg.ActiveAuthTokens(time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)); len(got) != 1 {
		t.Fatalf("expired=%v", got)
	}
	bad := `{"auth_token":"new-token","previous_auth_tokens":[{"token":"old-token"}]}`
	if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerConfig(path); err == nil {
		t.Fatal("accepted previous token without expiry")
	}
}
