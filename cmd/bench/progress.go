package main

import (
	"encoding/json"
	"io"
	"mygotunnel/internal/diagnostics"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type progress struct{ tx, rx atomic.Int64 }
type meterWriter struct {
	io.Writer
	p *progress
}

func (w meterWriter) Write(b []byte) (int, error) {
	n, e := w.Writer.Write(b)
	if w.p != nil {
		w.p.tx.Add(int64(n))
	}
	return n, e
}

type meterReader struct {
	io.Reader
	p *progress
}

func (r meterReader) Read(b []byte) (int, error) {
	n, e := r.Reader.Read(b)
	if r.p != nil {
		r.p.rx.Add(int64(n))
	}
	return n, e
}
func (p *progress) start(interval time.Duration, mode string, direct bool) func() {
	if interval == 0 {
		return func() {}
	}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(interval)
		defer t.Stop()
		last := time.Now()
		var tx, rx int64
		for {
			select {
			case <-stop:
				return
			case now := <-t.C:
				nx, ny := p.tx.Load(), p.rx.Load()
				sec := now.Sub(last).Seconds()
				sample := diagnostics.Snapshot()
				_ = json.NewEncoder(os.Stderr).Encode(map[string]any{"event": "progress", "mode": mode, "direct": direct, "uploaded_bytes": nx, "downloaded_bytes": ny, "upload_mbps": float64(nx-tx) * 8 / sec / 1e6, "download_mbps": float64(ny-rx) * 8 / sec / 1e6, "runtime": sample})
				last = now
				tx = nx
				rx = ny
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(stop) }); <-done }
}
