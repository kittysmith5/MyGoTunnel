package diagnostics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPrivateExclusiveMetricsAndStop(t *testing.T) {
	p := filepath.Join(t.TempDir(), "metrics.jsonl")
	stop, e := start(p, 5*time.Millisecond)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := Start(p); e == nil {
		t.Fatal("overwrote metrics")
	}
	time.Sleep(20 * time.Millisecond)
	stop()
	stop()
	before, _ := os.ReadFile(p)
	time.Sleep(10 * time.Millisecond)
	after, _ := os.ReadFile(p)
	if string(before) != string(after) {
		t.Fatal("writer continued after stop")
	}
	var last Sample
	lines := strings.Split(strings.TrimSpace(string(after)), "\n")
	if len(lines) < 2 {
		t.Fatal("missing samples")
	}
	for _, line := range lines {
		var s Sample
		if e := json.Unmarshal([]byte(line), &s); e != nil {
			t.Fatal(e)
		}
		if s.TotalAlloc < last.TotalAlloc || s.Mallocs < last.Mallocs || s.CPUSeconds < last.CPUSeconds {
			t.Fatal("non-monotonic metrics")
		}
		last = s
	}
	info, _ := os.Stat(p)
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		t.Fatal("public metrics file")
	}
}
func TestDisabledMetrics(t *testing.T) {
	stop, e := Start("")
	if e != nil {
		t.Fatal(e)
	}
	stop()
	stop()
}
