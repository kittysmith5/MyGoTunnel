package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSOCKSRotationRequiresCurrentCredentials(t *testing.T) {
	for _, tc := range []struct {
		name, fields   string
		valid, enabled bool
	}{
		{name: "absent authentication", valid: true},
		{name: "explicit null authentication", fields: `,"socks_auth":null`, valid: true},
		{name: "previous alone", fields: `,"previous_socks_auth":[{"username":"old","password":"old-pass","expires_at":"2099-01-01T00:00:00Z"}]`},
		{name: "null current with previous", fields: `,"socks_auth":null,"previous_socks_auth":[{"username":"old","password":"old-pass","expires_at":"2099-01-01T00:00:00Z"}]`},
		{name: "expired previous alone", fields: `,"previous_socks_auth":[{"username":"old","password":"old-pass","expires_at":"2000-01-01T00:00:00Z"}]`},
		{name: "invalid current", fields: `,"socks_auth":{"username":"new"},"previous_socks_auth":[{"username":"old","password":"old-pass","expires_at":"2099-01-01T00:00:00Z"}]`},
		{name: "current and previous", fields: `,"socks_auth":{"username":"new","password":"new-pass"},"previous_socks_auth":[{"username":"old","password":"old-pass","expires_at":"2099-01-01T00:00:00Z"}]`, valid: true, enabled: true},
		{name: "legacy current and previous", fields: `,"socks_username":"new","socks_password":"new-pass","previous_socks_auth":[{"username":"old","password":"old-pass","expires_at":"2099-01-01T00:00:00Z"}]`, valid: true, enabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "client.json")
			data := `{"remote_addr":"127.0.0.1:8443","auth_token":"test-token"` + tc.fields + `}`
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadClientConfig(path)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
			if err == nil {
				_, enabled := cfg.SOCKSCredentialSet(time.Now())
				if enabled != tc.enabled {
					t.Fatalf("authentication enabled=%v, want %v", enabled, tc.enabled)
				}
			}
		})
	}
}
