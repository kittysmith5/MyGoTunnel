package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHTTPSConfigBoundsAndIndexSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "page.html")
	if err := os.WriteFile(path, []byte("public page"), 0600); err != nil {
		t.Fatal(err)
	}
	c := HTTPSConfig{Enabled: true, IndexFile: path}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if string(c.HTML()) != "public page" {
		t.Fatal("index not snapshotted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []HTTPSConfig{{Enabled: true, IndexFile: link}, {Enabled: true, IndexFile: dir}, {Enabled: true, IndexFile: filepath.Join(dir, "missing-secret")}, {Enabled: true, MaxConnections: -1}, {Enabled: true, PreAuthRatePerIP: 10001}} {
		if err := bad.validate(); err == nil || strings.Contains(err.Error(), "missing-secret") {
			t.Fatalf("invalid/unsafe error: %v", err)
		}
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 65537)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.validate(); err == nil {
		t.Fatal("oversized index accepted")
	}
	for _, setup := range []int{1, 4, 128} {
		e, err := (HTTPSConfig{}).Effective(setup, 1024)
		if err != nil || e.MaxPreAuthPerIP != min(32, max(1, (setup+3)/4)) || e.MaxConnections != 64 || e.PreAuthRatePerIP != 20 || e.PreAuthBurstPerIP != 40 {
			t.Fatalf("defaults: %+v %v", e, err)
		}
	}
	if _, err := (HTTPSConfig{MaxPreAuthPerIP: 5}).Effective(4, 1024); err == nil {
		t.Fatal("invalid runtime cap")
	}
	configPath := filepath.Join(dir, "server.json")
	if err := os.WriteFile(configPath, []byte(`{"auth_token":"test-only","https_entry":{"enabled":true,"pre_auth_rate_per_ip":-1}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerConfig(configPath); err == nil {
		t.Fatal("invalid JSON policy accepted")
	}
	if err := os.WriteFile(configPath, []byte(`{"auth_token":"test-only","https_entry":{"enabled":true}}`), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadServerConfig(configPath)
	if err != nil || !loaded.HTTPS.Enabled || len(loaded.HTTPS.HTML()) == 0 {
		t.Fatal("HTTPS configuration not loaded")
	}
}
