package buildinfo

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestIdentityJSON(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b); err != nil {
		t.Fatal(err)
	}
	var i Info
	if err := json.Unmarshal(b.Bytes(), &i); err != nil {
		t.Fatal(err)
	}
	if i.Version == "" || i.Commit == "" || i.Platform == "" {
		t.Fatalf("missing identity: %+v", i)
	}
}
