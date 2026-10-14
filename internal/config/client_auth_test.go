package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSOCKSAuth(t *testing.T) {
	for _, tc := range []struct {
		name string
		auth *SOCKSAuth
		ok   bool
	}{
		{"absent", nil, true}, {"valid", &SOCKSAuth{"user", "pass"}, true}, {"empty", &SOCKSAuth{}, false}, {"missing password", &SOCKSAuth{Username: "user"}, false}, {"long", &SOCKSAuth{strings.Repeat("x", 256), "pass"}, false}, {"maximum", &SOCKSAuth{strings.Repeat("x", 255), strings.Repeat("p", 255)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "client.json")
			c := ClientConfig{RemoteAddr: "localhost:8443", AuthToken: "test", SOCKSAuth: tc.auth}
			b, _ := json.Marshal(c)
			if e := os.WriteFile(p, b, 0600); e != nil {
				t.Fatal(e)
			}
			got, e := LoadClientConfig(p)
			if (e == nil) != tc.ok {
				t.Fatalf("load: %v", e)
			}
			if e == nil && tc.auth != nil && *got.SOCKSAuth != *tc.auth {
				t.Fatal("auth not loaded")
			}
		})
	}
}
