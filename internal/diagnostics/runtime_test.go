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

func TestSnapshotIncludesHeapAndProcessState(t *testing.T) {
	s := Snapshot()
	if s.Goroutines < 1 || s.HeapAlloc == 0 || s.HeapAlloc > s.HeapInuse || s.HeapReleased > s.HeapIdle {
		t.Fatalf("inconsistent heap/process sample: %+v", s)
	}
	if runtime.GOOS == "linux" && (!s.FDAvailable || s.FDCount < 1 || !s.RSSAvailable || s.RSSBytes == 0) {
		t.Fatalf("missing Linux process sample: %+v", s)
	}
	if runtime.GOOS == "linux" {
		f, err := os.CreateTemp(t.TempDir(), "fd")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		next := Snapshot()
		if next.FDCount < s.FDCount+1 {
			t.Fatalf("new descriptor not counted: before=%d after=%d", s.FDCount, next.FDCount)
		}
	}
}
