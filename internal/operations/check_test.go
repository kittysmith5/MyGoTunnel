package operations

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMalformedConfigDoesNotDiscloseInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"auth_token":"SECRET_VALUE","remote_addr":SECRET_VALUE}`), 0600); err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	code := Check("client", path, false)
	os.Stdout = old
	w.Close()
	data, _ := io.ReadAll(r)
	r.Close()
	if code != 1 || strings.Contains(string(data), "SECRET_VALUE") || !strings.Contains(string(data), "CONFIG_INVALID") {
		t.Fatalf("unsafe diagnostic %d %s", code, data)
	}
}
