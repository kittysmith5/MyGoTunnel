package operations

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"mygotunnel/internal/config"
)

func TestConfigCheckRejectsUnusableListenPortBeforeRestart(t *testing.T) {
	for _, role := range []string{"client", "server"} {
		t.Run(role, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if role == "server" {
				if _, err := config.InitializeServer(path, "127.0.0.1:8443", "127.0.0.1:8443"); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte(`{"remote_addr":"server.invalid:8443","auth_token":"test-token"}`), 0600); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var cfg map[string]any
			if err := json.Unmarshal(data, &cfg); err != nil {
				t.Fatal(err)
			}
			if role == "client" {
				cfg["local_addr"] = "127.0.0.1:70000"
			} else {
				cfg["listen_addr"] = "127.0.0.1:70000"
			}
			data, err = json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			original := os.Stdout
			os.Stdout = w
			code := Check(role, path, false)
			os.Stdout = original
			w.Close()
			output, err := io.ReadAll(r)
			r.Close()
			if err != nil {
				t.Fatal(err)
			}
			var result Result
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatal(err)
			}
			if code != 1 || result.OK || result.Code != "CONFIG_INVALID" {
				t.Fatalf("code=%d result=%+v", code, result)
			}
		})
	}
}
