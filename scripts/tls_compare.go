//go:build ignore

// Run explicitly with go run scripts/tls_compare.go. It sends normal HTTPS GETs
// to a configured test entrance, never proxy credentials or application data.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mygotunnel/internal/utlsconn"
	"net/http"
	"os"
	"runtime"
	"sort"
	"syscall"
	"time"
)

type block struct {
	Cache       bool    `json:"cache"`
	Samples     int     `json:"samples"`
	Resumed     int     `json:"resumed"`
	Failures    int     `json:"failures"`
	TLSP50MS    float64 `json:"tls_p50_ms"`
	TLSP95MS    float64 `json:"tls_p95_ms"`
	TLSP99MS    float64 `json:"tls_p99_ms"`
	CPUPerOpMS  float64 `json:"client_cpu_ms_per_op"`
	BytesPerOp  uint64  `json:"client_alloc_bytes_per_op"`
	AllocsPerOp uint64  `json:"client_allocs_per_op"`
}

func cpuSeconds() float64 {
	var r syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &r); err != nil {
		panic("CPU statistics unavailable")
	}
	return float64(r.Utime.Sec+r.Stime.Sec) + float64(r.Utime.Usec+r.Stime.Usec)/1e6
}

func request(remote, sni string, cache bool) (utlsconn.DialTimings, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, timings, err := utlsconn.DialWithOptions(ctx, remote, sni, "", utlsconn.Options{SessionCache: cache})
	if err != nil {
		return timings, err
	}
	defer c.Close()
	if err = c.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return timings, err
	}
	// Read the response so TLS 1.3 session tickets reach the cache.
	if _, err = fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", sni); err != nil {
		return timings, err
	}
	response, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return timings, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return timings, fmt.Errorf("unexpected HTTP status")
	}
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 65536))
	return timings, err
}

func main() {
	remote := flag.String("remote", "", "test server host:port")
	sni := flag.String("sni", "", "CA-verified certificate hostname")
	n := flag.Int("n", 50, "samples per A/B/B/A block (5..1000)")
	flag.Parse()
	if *remote == "" || *sni == "" || *n < 5 || *n > 1000 {
		fmt.Fprintln(os.Stderr, "invalid benchmark arguments")
		os.Exit(2)
	}
	results := make([]block, 0, 4)
	failed := false
	for _, enabled := range []bool{false, true, true, false} {
		if _, err := request(*remote, *sni, enabled); err != nil {
			fmt.Fprintln(os.Stderr, "benchmark warmup failed")
			os.Exit(1)
		}
		r := block{Cache: enabled, Samples: *n}
		durations := make([]float64, 0, *n)
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		cpu := cpuSeconds()
		for i := 0; i < *n; i++ {
			t, err := request(*remote, *sni, enabled)
			if err != nil {
				r.Failures++
				failed = true
				continue
			}
			if t.TLSResumed {
				r.Resumed++
			}
			durations = append(durations, float64(t.TLSDuration)/float64(time.Millisecond))
		}
		r.CPUPerOpMS = (cpuSeconds() - cpu) * 1000 / float64(*n)
		runtime.ReadMemStats(&after)
		r.BytesPerOp = (after.TotalAlloc - before.TotalAlloc) / uint64(*n)
		r.AllocsPerOp = (after.Mallocs - before.Mallocs) / uint64(*n)
		sort.Float64s(durations)
		if len(durations) > 0 {
			quantile := func(percent int) float64 { return durations[(len(durations)*percent+99)/100-1] }
			r.TLSP50MS, r.TLSP95MS, r.TLSP99MS = quantile(50), quantile(95), quantile(99)
		}
		results = append(results, r)
	}
	if json.NewEncoder(os.Stdout).Encode(results) != nil {
		os.Exit(1)
	}
	if failed {
		os.Exit(1)
	}
}
