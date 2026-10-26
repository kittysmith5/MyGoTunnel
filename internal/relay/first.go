package relay

import (
	"io"
	"time"
)

// firstCopy observes data availability, not HTTP TTFB or successful delivery.
// Preserve WriterTo/ReaderFrom dispatch; TLS endpoints cannot use TCP splice.
// Each instance is owned by one copy goroutine, with no per-read atomics/timers.
type firstCopy struct {
	started time.Time
	seen    bool
	elapsed time.Duration
	notify  func(time.Duration)
}

func (f *firstCopy) mark(n int) {
	if n > 0 && !f.seen {
		f.seen = true
		f.elapsed = time.Since(f.started)
		if f.notify != nil {
			f.notify(f.elapsed)
		}
	}
}

type firstReader struct {
	io.Reader
	first *firstCopy
}

func (r firstReader) Read(p []byte) (int, error) {
	n, e := r.Reader.Read(p)
	r.first.mark(n)
	return n, e
}
func (r firstReader) WriteTo(w io.Writer) (int64, error) {
	if wt, ok := r.Reader.(io.WriterTo); ok {
		return wt.WriteTo(firstWriter{w, r.first})
	}
	return io.Copy(w, struct{ io.Reader }{r})
}

type firstWriter struct {
	io.Writer
	first *firstCopy
}

func (w firstWriter) Write(p []byte) (int, error) { w.first.mark(len(p)); return w.Writer.Write(p) }
func (w firstWriter) ReadFrom(r io.Reader) (int64, error) {
	observed := firstReader{r, w.first}
	if rf, ok := w.Writer.(io.ReaderFrom); ok {
		return rf.ReadFrom(struct{ io.Reader }{observed})
	}
	return io.Copy(struct{ io.Writer }{w.Writer}, struct{ io.Reader }{observed})
}
