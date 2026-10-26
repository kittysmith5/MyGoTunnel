// Package quicstream implements the optional, experimental TCP carrier. Each
// reliable stream runs the existing AUTH/CONNECT protocol; DATAGRAMs are disabled.
package quicstream

import (
	"errors"
	"net"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

const ALPN = "mygotunnel-tcp/1"
const streamLimit = 64

func transportConfig() *quic.Config {
	return &quic.Config{HandshakeIdleTimeout: 2500 * time.Millisecond, MaxIdleTimeout: 2 * time.Minute, KeepAlivePeriod: 15 * time.Second,
		InitialStreamReceiveWindow: 256 << 10, MaxStreamReceiveWindow: 8 << 20, InitialConnectionReceiveWindow: 1 << 20, MaxConnectionReceiveWindow: 32 << 20,
		MaxIncomingStreams: streamLimit, MaxIncomingUniStreams: -1, InitialPacketSize: 1200, Allow0RTT: false}
}

type Stream struct {
	q                             *quic.Conn
	s                             *quic.Stream
	closed                        sync.Once
	writeMu                       sync.Mutex
	mu                            sync.Mutex
	writing, writeClosed, stopped bool
	release                       func()
	authorize                     func()
}

var _ net.Conn = (*Stream)(nil)

func (s *Stream) Read(p []byte) (int, error) { return s.s.Read(p) }
func (s *Stream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	if s.stopped || s.writeClosed {
		s.mu.Unlock()
		return 0, net.ErrClosed
	}
	s.writing = true
	s.mu.Unlock()
	n, e := s.s.Write(p)
	s.mu.Lock()
	s.writing = false
	s.mu.Unlock()
	return n, e
}
func (s *Stream) CloseWrite() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return net.ErrClosed
	}
	if s.writeClosed {
		return nil
	}
	if s.writing {
		return errors.New("concurrent QUIC stream half-close")
	}
	e := s.s.Close()
	if e == nil {
		s.writeClosed = true
	}
	return e
}
func (s *Stream) Close() error {
	s.closed.Do(func() {
		s.mu.Lock()
		s.stopped = true
		s.s.CancelRead(0x100)
		if s.writing {
			s.s.CancelWrite(0x100)
		} else if !s.writeClosed {
			_ = s.s.Close()
			s.writeClosed = true
		}
		s.mu.Unlock()
		if s.release != nil {
			s.release()
		}
	})
	return nil
}
func (s *Stream) LocalAddr() net.Addr                { return s.q.LocalAddr() }
func (s *Stream) RemoteAddr() net.Addr               { return s.q.RemoteAddr() }
func (s *Stream) SetDeadline(t time.Time) error      { return s.s.SetDeadline(t) }
func (s *Stream) SetReadDeadline(t time.Time) error  { return s.s.SetReadDeadline(t) }
func (s *Stream) SetWriteDeadline(t time.Time) error { return s.s.SetWriteDeadline(t) }
func (s *Stream) MarkAuthenticated() {
	if s.authorize != nil {
		s.authorize()
	}
}
func (s *Stream) IsTCPStream() bool { return true }
