// Package diagnostics writes opt-in, credential-free runtime measurements.
package diagnostics

import (
	"encoding/json"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Sample struct {
	Time         time.Time `json:"time"`
	CPUSeconds   float64   `json:"cpu_seconds"`
	CPUAvailable bool      `json:"cpu_available"`
	RSSBytes     uint64    `json:"rss_bytes"`
	RSSAvailable bool      `json:"rss_available"`
	HeapAlloc    uint64    `json:"heap_alloc_bytes"`
	TotalAlloc   uint64    `json:"total_alloc_bytes"`
	Mallocs      uint64    `json:"mallocs"`
	NumGC        uint32    `json:"gc_cycles"`
}

func Snapshot() Sample {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	s := Sample{Time: time.Now().UTC(), HeapAlloc: m.HeapAlloc, TotalAlloc: m.TotalAlloc, Mallocs: m.Mallocs, NumGC: m.NumGC}
	s.CPUSeconds, s.CPUAvailable = cpuSeconds()
	if b, e := os.ReadFile("/proc/self/statm"); e == nil {
		f := strings.Fields(string(b))
		if len(f) > 1 {
			if pages, e := strconv.ParseUint(f[1], 10, 64); e == nil {
				s.RSSBytes = pages * uint64(os.Getpagesize())
				s.RSSAvailable = true
			}
		}
	}
	return s
}

// Start writes an initial sample then one per second. The file is exclusive and
// private; default empty path creates neither a file nor a sampling goroutine.
func Start(path string) (func(), error) { return start(path, time.Second) }
func start(path string, interval time.Duration) (func(), error) {
	if path == "" {
		return func() {}, nil
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if e != nil {
		return nil, e
	}
	encoder := json.NewEncoder(f)
	if e = encoder.Encode(Snapshot()); e != nil {
		f.Close()
		return nil, e
	}
	stop, done := make(chan struct{}), make(chan struct{})
	var once sync.Once
	go func() {
		defer close(done)
		defer f.Close()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				_ = encoder.Encode(Snapshot())
				return
			case <-ticker.C:
				if encoder.Encode(Snapshot()) != nil {
					return
				}
			}
		}
	}()
	return func() { once.Do(func() { close(stop) }); <-done }, nil
}
