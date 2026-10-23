package ingress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mygotunnel/internal/tunnel"
)

const EntryTimeout = 5 * time.Second

type Counters struct {
	TLSFailed, PreAuthTimeout, IPLimited, HTTPCapacityRejected                    atomic.Uint64
	HTTPRequests, HTTPUnparsed, HTTPInternalErrors, HTTPWriteFailed, AuthRejected atomic.Uint64
	HTTPActive, PreAuthActive                                                     atomic.Int64
}

func (m *Counters) Attrs() []any {
	return []any{"ingress_tls_failed", m.TLSFailed.Load(), "ingress_pre_auth_timeout", m.PreAuthTimeout.Load(), "ingress_ip_limited", m.IPLimited.Load(), "ingress_http_capacity_rejected", m.HTTPCapacityRejected.Load(), "ingress_http_requests", m.HTTPRequests.Load(), "ingress_http_unparsed", m.HTTPUnparsed.Load(), "ingress_http_internal_errors", m.HTTPInternalErrors.Load(), "ingress_http_write_failed", m.HTTPWriteFailed.Load(), "ingress_auth_rejected", m.AuthRejected.Load(), "ingress_http_active", m.HTTPActive.Load(), "ingress_pre_auth_active", m.PreAuthActive.Load()}
}

type Server struct {
	Metrics  Counters
	guard    *Guard
	listener *handoffListener
	http     *http.Server
	served   chan struct{}
	slots    chan struct{}
	index    []byte
}

// New starts one process-wide HTTP server. Positive limits are required.
func New(index []byte, maxHTTP, perIP, rate, burst int) (*Server, error) {
	if maxHTTP < 1 || perIP < 1 || rate < 1 || burst < 1 || len(index) > 65536 {
		return nil, errors.New("invalid HTTPS entrance options")
	}
	s := &Server{guard: NewGuard(perIP, rate, burst), listener: &handoffListener{incoming: make(chan net.Conn), closed: make(chan struct{})}, served: make(chan struct{}), slots: make(chan struct{}, maxHTTP), index: bytes.Clone(index)}
	s.http = &http.Server{
		Handler:                      http.HandlerFunc(s.handleHTTP),
		DisableGeneralOptionsHandler: true,
		ReadHeaderTimeout:            EntryTimeout,
		WriteTimeout:                 EntryTimeout,
		IdleTimeout:                  15 * time.Second,
		MaxHeaderBytes:               16 << 10,
		ErrorLog:                     log.New(safeHTTPLog{&s.Metrics.HTTPInternalErrors}, "", 0),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, c.(*webConn))
		},
		ConnState: func(c net.Conn, state http.ConnState) {
			if state == http.StateClosed {
				wc := c.(*webConn)
				if wc.initial() {
					if wc.timedOut.Load() {
						s.Metrics.PreAuthTimeout.Add(1)
					} else {
						s.Metrics.HTTPUnparsed.Add(1)
					}
				}
				close(wc.finished)
			}
		},
	}
	go func() {
		defer close(s.served)
		if err := s.http.Serve(s.listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			s.Metrics.HTTPInternalErrors.Add(1)
		}
	}()
	return s, nil
}

// Accept is suitable for admission.AcceptGate and runs before TLS and global slots.
func (s *Server) Accept(c net.Conn) (func(), bool) {
	release, ok := s.guard.Acquire(c.RemoteAddr())
	if !ok {
		s.Metrics.IPLimited.Add(1)
		return nil, false
	}
	s.Metrics.PreAuthActive.Add(1)
	return sync.OnceFunc(func() { release(); s.Metrics.PreAuthActive.Add(-1) }), true
}

// Route returns a reader only after AUTH success and OK. A nil reader with no
// error means HTTP owned and completed the connection. The caller closes c.
func (s *Server) Route(ctx context.Context, c net.Conn, started time.Time, releaseSetup, releasePreAuth func(), authenticate func(string) error) (*bufio.Reader, error) {
	deadline := started.Add(EntryTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := c.SetDeadline(deadline); err != nil {
		return nil, err
	}
	handshake, ok := c.(interface{ HandshakeContext(context.Context) error })
	if !ok {
		return nil, errors.New("HTTPS entrance requires TLS")
	}
	if err := handshake.HandshakeContext(ctx); err != nil {
		s.Metrics.TLSFailed.Add(1)
		s.countTimeout(err)
		return nil, err
	}
	reader := bufio.NewReader(c)
	raw, line, candidate, err := classify(reader)
	if err != nil {
		s.countTimeout(err)
		return nil, err
	}
	if candidate {
		if err := authenticate(line); err == nil {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if err := tunnel.SendOK(c); err != nil {
				s.countTimeout(err)
				return nil, err
			}
			if err := c.SetDeadline(time.Time{}); err != nil {
				return nil, err
			}
			releasePreAuth()
			return reader, nil
		}
		s.Metrics.AuthRejected.Add(1)
	}
	if !time.Now().Before(deadline) {
		s.Metrics.PreAuthTimeout.Add(1)
		return nil, context.DeadlineExceeded
	}
	select {
	case s.slots <- struct{}{}:
	default:
		s.Metrics.HTTPCapacityRejected.Add(1)
		return nil, nil
	}
	s.Metrics.HTTPActive.Add(1)
	wc := &webConn{Conn: c, reader: io.MultiReader(bytes.NewReader(raw), reader), firstDeadline: deadline, first: true, finished: make(chan struct{}), releaseHeader: sync.OnceFunc(func() { releasePreAuth(); releaseSetup() })}
	if tc, ok := c.(interface{ ConnectionState() tls.ConnectionState }); ok {
		wc.tlsState = tc.ConnectionState()
	}
	wc.release = func() { <-s.slots; s.Metrics.HTTPActive.Add(-1) }
	select {
	case s.listener.incoming <- wc:
		<-wc.finished // Keep admission's global count and shutdown ownership until close.
	case <-s.listener.closed:
		_ = wc.Close()
	case <-ctx.Done():
		_ = wc.Close()
	}
	return nil, nil
}

// classify consumes a bounded AUTH candidate only. Ordinary HTTP is untouched;
// consumed bytes are returned verbatim even on parse failure or buffer overflow.
// raw borrows r's buffer: replay it completely before reading r again.
func classify(r *bufio.Reader) ([]byte, string, bool, error) {
	prefix, err := r.Peek(5)
	if err != nil && len(prefix) == 0 {
		return nil, "", false, err
	}
	if !bytes.HasPrefix(prefix, []byte("AUTH ")) && (len(prefix) == 0 || (prefix[0] != ' ' && prefix[0] < 0x80)) {
		return nil, "", false, nil
	}
	raw, readErr := r.ReadSlice('\n') // Reader capacity is exactly the 4096-byte control limit.
	if readErr != nil && !errors.Is(readErr, bufio.ErrBufferFull) {
		return nil, "", false, readErr
	}
	line, parseErr := tunnel.ParseControlLine(raw)
	return raw, line, parseErr == nil && strings.HasPrefix(line, "AUTH "), nil
}

func (s *Server) countTimeout(err error) {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		s.Metrics.PreAuthTimeout.Add(1)
	}
}

type connKey struct{}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	c := r.Context().Value(connKey{}).(*webConn)
	if r.TLS == nil {
		r.TLS = &c.tlsState
	}
	if err := c.headerComplete(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			c.timedOut.Store(true)
		}
		_ = c.Close()
		return
	}
	s.Metrics.HTTPRequests.Add(1)
	c.requests++
	withBody := r.ContentLength != 0 || len(r.TransferEncoding) != 0
	if c.requests >= 8 || withBody {
		r.Close = true
		w.Header().Set("Connection", "close")
	}
	if withBody {
		// net/http may otherwise drain an unread body after the handler returns.
		// Expire reads now, without disturbing the bounded response write.
		if err := c.SetReadDeadline(time.Now()); err != nil {
			_ = c.Close()
			return
		}
	}
	status, body := http.StatusOK, s.index
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		status, body = http.StatusMethodNotAllowed, []byte("Method Not Allowed\n")
		w.Header().Set("Allow", "GET, HEAD")
	} else if r.URL.Path != "/" {
		status, body = http.StatusNotFound, []byte("Not Found\n")
	}
	if status == http.StatusOK {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	var writeErr error
	if r.Method != http.MethodHead {
		_, writeErr = w.Write(body)
	}
	if writeErr == nil {
		writeErr = http.NewResponseController(w).Flush()
	}
	if writeErr != nil {
		s.Metrics.HTTPWriteFailed.Add(1)
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	err := s.http.Shutdown(ctx)
	if err != nil {
		_ = s.http.Close()
	}
	return err
}

func (s *Server) Close() error {
	_ = s.listener.Close()
	err := s.http.Close()
	<-s.served
	return err
}

type safeHTTPLog struct{ count *atomic.Uint64 }

func (w safeHTTPLog) Write(p []byte) (int, error) { w.count.Add(1); return len(p), nil }

type handoffListener struct {
	incoming chan net.Conn
	closed   chan struct{}
	once     sync.Once
}

func (l *handoffListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.incoming:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *handoffListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *handoffListener) Addr() net.Addr { return &net.TCPAddr{} }

type webConn struct {
	net.Conn
	reader        io.Reader
	tlsState      tls.ConnectionState
	mu            sync.Mutex
	first         bool
	firstDeadline time.Time
	releaseHeader func()
	release       func()
	closeOnce     sync.Once
	finished      chan struct{}
	timedOut      atomic.Bool
	requests      int // HTTP/1 requests are handled sequentially on this connection.
}

func (c *webConn) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		c.timedOut.Store(true)
	}
	return n, err
}
func (c *webConn) initial() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.first }
func (c *webConn) clipped(t time.Time) time.Time {
	if c.first && (t.IsZero() || t.After(c.firstDeadline)) {
		return c.firstDeadline
	}
	return t
}
func (c *webConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Conn.SetReadDeadline(c.clipped(t))
}
func (c *webConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Conn.SetWriteDeadline(c.clipped(t))
}
func (c *webConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Conn.SetDeadline(c.clipped(t))
}
func (c *webConn) headerComplete() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.first {
		return nil
	}
	if !time.Now().Before(c.firstDeadline) {
		return context.DeadlineExceeded
	}
	c.first = false
	c.releaseHeader()
	if err := c.Conn.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	return c.Conn.SetWriteDeadline(time.Now().Add(EntryTimeout))
}
func (c *webConn) Close() error {
	var closeErr error
	c.closeOnce.Do(func() {
		_ = c.SetWriteDeadline(time.Now().Add(time.Second))
		closeErr = c.Conn.Close()
		c.release()
	})
	return closeErr
}
