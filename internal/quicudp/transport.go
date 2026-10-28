// Package quicudp carries one authenticated SOCKS UDP association per QUIC
// connection. The reliable stream is exclusively control; packets are DATAGRAMs.
package quicudp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/ingress"
)

const (
	handshakeTimeout = 5 * time.Second
	// ReassemblyTimeout covers network transmission, independently of the
	// application's much shorter local queue-age policy.
	ReassemblyTimeout = 2 * time.Second
)

var (
	ErrNotAuthorized   = errors.New("QUIC UDP association is not authorized")
	ErrAuthRejected    = errors.New("QUIC UDP authentication rejected")
	ErrLimit           = errors.New("QUIC UDP resource limit reached")
	errControlProtocol = errors.New("unexpected UDP control data")
)

const (
	closeNormal       quic.ApplicationErrorCode = 0
	closeAuthRejected quic.ApplicationErrorCode = 0x100
	closeTimeout      quic.ApplicationErrorCode = 0x101
	closeProtocol     quic.ApplicationErrorCode = 0x102
	closeFailure      quic.ApplicationErrorCode = 0x103
	closeLimit        quic.ApplicationErrorCode = 0x104
)

func normalizeRemoteError(err error) error {
	var application *quic.ApplicationError
	if !errors.As(err, &application) || !application.Remote {
		return err
	}
	switch application.ErrorCode {
	case closeNormal:
		return io.EOF
	case closeAuthRejected:
		return ErrAuthRejected
	case closeTimeout:
		return os.ErrDeadlineExceeded
	case closeLimit:
		return ErrLimit
	default:
		return err
	}
}

func transportConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout:           handshakeTimeout / 2,
		MaxIdleTimeout:                 2 * time.Minute,
		KeepAlivePeriod:                15 * time.Second,
		InitialStreamReceiveWindow:     8192,
		MaxStreamReceiveWindow:         8192,
		InitialConnectionReceiveWindow: 8192,
		MaxConnectionReceiveWindow:     8192,
		MaxIncomingStreams:             1,
		MaxIncomingUniStreams:          -1,
		InitialPacketSize:              1200,
		DisablePathMTUDiscovery:        false,
		EnableDatagrams:                true,
		Allow0RTT:                      false,
	}
}

// Conn's net.Conn methods operate on the reliable control stream. Call
// EnableDatagrams only after both AUTH and UDP setup have succeeded. From then
// on ReadPacket/WritePacket carry business data and the stream owns liveness.
type Conn struct {
	q                  *quic.Conn
	resources          *datagram.Resources
	maxAge             time.Duration
	streamOnce         sync.Once
	stream             *quic.Stream
	streamErr          error
	streamCtx          context.Context
	streamStop         context.CancelFunc
	packets            chan datagram.Packet
	done               chan struct{}
	failOnce           sync.Once
	closeOnce          sync.Once
	workers            sync.WaitGroup
	writeMu            sync.Mutex
	id                 uint32
	wire               [compactWireSize]byte
	compact            bool
	compactLimit       int
	compactProbe       time.Time
	bulkUntil          time.Time
	lastBulk           time.Time
	enabled            atomic.Bool
	monitorOnce        sync.Once
	mu                 sync.Mutex
	closing            bool
	cause              error
	readUntil          time.Time
	writeUntil         time.Time
	readChange         chan struct{}
	writing            bool
	writeTimer         *time.Timer
	streamTimer        *time.Timer
	preAuthDrops       atomic.Uint64
	malformedDrops     atomic.Uint64
	resourceDrops      atomic.Uint64
	fragmentLimitDrops atomic.Uint64
	queueFullDrops     atomic.Uint64
	queueExpiredDrops  atomic.Uint64
	fragmentReceives   atomic.Uint64
	fragmentEnqueues   atomic.Uint64
	incompleteExpired  atomic.Uint64
	cleanup            func()
}

var _ net.Conn = (*Conn)(nil)

func newConn(q *quic.Conn, stream *quic.Stream, resources *datagram.Resources, maxAge time.Duration, cleanup func()) (*Conn, error) {
	if !q.ConnectionState().SupportsDatagrams.Remote {
		_ = q.CloseWithError(1, "datagrams required")
		return nil, errors.New("peer does not support QUIC datagrams")
	}
	if resources == nil {
		resources = datagram.DefaultResources
	}
	if maxAge <= 0 {
		maxAge = datagram.DefaultMaxAge
	}
	streamCtx, streamStop := context.WithTimeout(q.Context(), handshakeTimeout)
	c := &Conn{q: q, resources: resources, maxAge: maxAge, stream: stream,
		streamCtx: streamCtx, streamStop: streamStop, packets: make(chan datagram.Packet, 16),
		compact: q.ConnectionState().TLS.NegotiatedProtocol == ALPNCompact, compactLimit: compactWireSize,
		done: make(chan struct{}), readChange: make(chan struct{}), cleanup: cleanup}
	if stream != nil {
		c.streamOnce.Do(func() {})
		streamStop()
	}
	c.workers.Add(1)
	go c.receivePackets()
	context.AfterFunc(q.Context(), func() { c.fail(context.Cause(q.Context())) })
	return c, nil
}

func (c *Conn) control() (*quic.Stream, error) {
	c.streamOnce.Do(func() {
		defer c.streamStop()
		stream, err := c.q.AcceptStream(c.streamCtx)
		c.streamErr = normalizeRemoteError(err)
		if c.streamErr != nil {
			c.mu.Lock()
			if !c.readUntil.IsZero() && !time.Now().Before(c.readUntil) {
				c.streamErr = os.ErrDeadlineExceeded
			}
			c.mu.Unlock()
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		c.stream = stream
		if c.streamTimer != nil {
			c.streamTimer.Stop()
		}
		_ = c.stream.SetReadDeadline(c.readUntil)
		_ = c.stream.SetWriteDeadline(c.writeUntil)
	})
	return c.stream, c.streamErr
}

func (c *Conn) Read(p []byte) (int, error) {
	s, err := c.control()
	if err != nil {
		return 0, err
	}
	n, err := s.Read(p)
	return n, normalizeRemoteError(err)
}

func (c *Conn) Write(p []byte) (int, error) {
	s, err := c.control()
	if err != nil {
		return 0, err
	}
	n, err := s.Write(p)
	return n, normalizeRemoteError(err)
}

// EnableDatagrams does not authenticate. The caller must have completed the
// authenticated UDP control exchange; pre-enable receive events are discarded.
func (c *Conn) EnableDatagrams() {
	c.monitorOnce.Do(func() {
		c.mu.Lock()
		if c.closing {
			c.mu.Unlock()
			return
		}
		c.enabled.Store(true)
		c.workers.Add(1)
		c.mu.Unlock()
		go func() {
			defer c.workers.Done()
			s, err := c.control()
			if err == nil {
				var b [1]byte
				var n int
				n, err = s.Read(b[:])
				if n != 0 {
					err = errControlProtocol
				}
			}
			c.fail(err)
		}()
	})
}

func (c *Conn) receivePackets() {
	defer c.workers.Done()
	defer close(c.packets)
	r := NewReassembler(c.resources, ReassemblyTimeout)
	defer r.Close()
	defer func() { c.incompleteExpired.Store(r.Stats().ExpiredPackets) }()
	for {
		err := c.receiveWindow(r)
		r.Expire(time.Now())
		c.incompleteExpired.Store(r.Stats().ExpiredPackets)
		if errors.Is(err, context.DeadlineExceeded) && c.q.Context().Err() == nil {
			continue
		}
		c.fail(err)
		return
	}
}

// One cancelable receive context is shared by every fragment in a window.
// Scope its cancellation here so each path releases the timer immediately.
func (c *Conn) receiveWindow(r *Reassembler) error {
	ctx, cancel := context.WithTimeout(c.q.Context(), 100*time.Millisecond)
	defer cancel()
	delivered := 0
	for {
		wire, err := c.q.ReceiveDatagram(ctx)
		if err != nil {
			return err
		}
		c.fragmentReceives.Add(1)
		if !c.enabled.Load() {
			c.preAuthDrops.Add(1)
			continue
		}
		packet, complete, err := c.decodePacket(r, wire)
		c.incompleteExpired.Store(r.Stats().ExpiredPackets)
		if err != nil {
			switch {
			case errors.Is(err, datagram.ErrResourceLimit):
				c.resourceDrops.Add(1)
			case errors.Is(err, ErrFragmentLimit):
				c.fragmentLimitDrops.Add(1)
			default:
				c.malformedDrops.Add(1)
			}
			continue
		}
		if !complete {
			continue // Malformed, resource-limited and incomplete UDP are dropped.
		}
		packet.At = time.Now() // Local queue age begins after complete reassembly.
		select {
		case c.packets <- packet:
		case <-c.done:
			packet.Release()
			return c.failure()
		default:
			c.queueFullDrops.Add(1)
			packet.Release()
		}
		delivered++
		if delivered%8 == 0 && len(c.packets) > 0 {
			// A coalesced QUIC receive batch can otherwise fill the small
			// complete-packet channel before its runnable consumer gets CPU.
			runtime.Gosched()
		}
	}
}

// Compact frames are only accepted after ALPN negotiation and authorization.
// Borrowed payload storage has the same process budget as fragmented packets.
const compactWireSize = 1415 // quic-go's conservative payload at its 1452-byte ceiling

func (c *Conn) decodePacket(r *Reassembler, wire []byte) (datagram.Packet, bool, error) {
	if c.compact && len(wire) >= 2 && wire[0] == 'P' && wire[1] == 2 {
		if len(wire) <= 2 || len(wire) > compactWireSize {
			return datagram.Packet{}, false, ErrMalformedFragment
		}
		packet, err := c.resources.Borrow(len(wire) - 2)
		if err != nil {
			return datagram.Packet{}, false, err
		}
		copy(packet.Data, wire[2:])
		return packet, true, nil
	}
	return r.Push(wire, time.Now())
}

func (c *Conn) ReadPacket() (datagram.Packet, error) {
	if !c.enabled.Load() {
		return datagram.Packet{}, ErrNotAuthorized
	}
	for {
		c.mu.Lock()
		until, changed := c.readUntil, c.readChange
		c.mu.Unlock()
		var expiry <-chan time.Time
		var timer *time.Timer
		if !until.IsZero() {
			if !time.Now().Before(until) {
				return datagram.Packet{}, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(until))
			expiry = timer.C
		}
		select {
		case packet, ok := <-c.packets:
			if timer != nil {
				timer.Stop()
			}
			if !ok {
				return datagram.Packet{}, c.failure()
			}
			if !packet.At.IsZero() && time.Since(packet.At) >= c.maxAge {
				c.queueExpiredDrops.Add(1)
				packet.Release()
				continue
			}
			return packet, nil
		case <-c.done:
			if timer != nil {
				timer.Stop()
			}
			return datagram.Packet{}, c.failure()
		case <-expiry:
			return datagram.Packet{}, os.ErrDeadlineExceeded
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		}
	}
}

// WritePacket may block when QUIC's bounded send queue is full. Its independent
// write deadline aborts this association, interrupting SendDatagram without a
// per-packet goroutine or an unbounded application send queue.
func (c *Conn) WritePacket(packet []byte) error {
	return c.writeSession(func() error { return c.writePacketLocked(packet, nil) })
}

// WritePacketQueue keeps at most one large and one small payload in flight.
// Existing v1 packet IDs allow fragments of different packets to interleave.
// A small packet can run after eight large fragments, without splitting TLS
// frames, adding an unbounded queue, or extending the large packet's deadline.
func (c *Conn) WritePacketQueue(queue interface {
	TryPop() (datagram.Packet, bool)
}, timeout time.Duration) (int, error) {
	sent := 0
	err := c.writeSession(func() error {
		var inFlight datagram.Packet
		interleave := func() error {
			small, ok := queue.(interface {
				TryPopSmallExcept(int, datagram.Packet) (datagram.Packet, bool)
			})
			if !ok || sent >= 32 {
				return nil
			}
			packet, ok := small.TryPopSmallExcept(compactWireSize-2, inFlight)
			if !ok {
				return nil
			}
			defer packet.Release()
			sent++
			return c.writePacketLocked(packet.Data, nil)
		}
		for sent < 32 {
			packet, ok := queue.TryPop()
			if !ok {
				return nil
			}
			sent++
			inFlight = packet
			e := c.SetWriteDeadline(time.Now().Add(timeout))
			if e == nil {
				e = c.writePacketLocked(packet.Data, interleave)
			}
			packet.Release()
			inFlight = datagram.Packet{}
			if e != nil {
				return e
			}
		}
		return nil
	})
	return sent, err
}
func (c *Conn) writeSession(write func() error) error {
	if !c.enabled.Load() {
		return ErrNotAuthorized
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	if !c.writeUntil.IsZero() && !time.Now().Before(c.writeUntil) {
		c.mu.Unlock()
		return os.ErrDeadlineExceeded
	}
	c.writing = true
	c.armWriteTimerLocked()
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.writing = false
		if c.writeTimer != nil {
			c.writeTimer.Stop()
		}
		c.mu.Unlock()
	}()
	return write()
}
func (c *Conn) writePacketLocked(packet []byte, interleave func() error) error {
	count, err := FragmentCount(len(packet))
	if err != nil {
		return err
	}
	id := c.id
	c.id++
	if c.compact && c.compactReady(len(packet), time.Now()) && len(packet)+2 <= compactWireSize &&
		(len(packet)+2 <= c.compactLimit || !time.Now().Before(c.compactProbe)) {
		c.wire[0], c.wire[1] = 'P', 2
		copy(c.wire[2:], packet)
		err = c.q.SendDatagram(c.wire[:len(packet)+2])
		if err == nil {
			c.fragmentEnqueues.Add(1)
			return nil
		}
		var tooLarge *quic.DatagramTooLargeError
		if !errors.As(err, &tooLarge) {
			select {
			case <-c.done:
				return c.failure()
			default:
				return err
			}
		}
		// SendDatagram rejects oversize frames before enqueueing. Retrying with
		// v1 fragments therefore cannot duplicate any business packet.
		c.compactLimit = int(tooLarge.MaxDatagramPayloadSize)
		c.compactProbe = time.Now().Add(time.Second)
	}
	for i := 0; i < count; i++ {
		fragment, buildErr := Fragment(c.wire[:0], packet, id, i)
		if buildErr != nil {
			return buildErr
		}
		if err = c.q.SendDatagram(fragment); err != nil {
			select {
			case <-c.done:
				return c.failure()
			default:
				return err
			}
		}
		c.fragmentEnqueues.Add(1)
		if (i+1)%8 == 0 && i+1 < count && interleave != nil {
			if e := interleave(); e != nil {
				return e
			}
		}
	}
	return nil
}

// Keep original packetization during the bounded start of a large-packet burst.
func (c *Conn) compactReady(size int, now time.Time) bool {
	if size <= fragmentPayload {
		return true
	}
	if c.bulkUntil.IsZero() || now.Sub(c.lastBulk) >= time.Second {
		ramp := min(time.Second, max(50*time.Millisecond, 3*c.q.ConnectionStats().SmoothedRTT))
		c.bulkUntil = now.Add(ramp)
	}
	c.lastBulk = now
	return !now.Before(c.bulkUntil)
}

func (c *Conn) armWriteTimerLocked() {
	if !c.writing || c.writeUntil.IsZero() {
		if c.writeTimer != nil {
			c.writeTimer.Stop()
		}
		return
	}
	if c.writeTimer != nil {
		c.writeTimer.Reset(time.Until(c.writeUntil))
		return
	}
	c.writeTimer = time.AfterFunc(time.Until(c.writeUntil), func() {
		c.mu.Lock()
		expired := c.writing && !c.writeUntil.IsZero() && !time.Now().Before(c.writeUntil)
		c.mu.Unlock()
		if expired {
			c.fail(os.ErrDeadlineExceeded)
		}
	})
}

func (c *Conn) fail(err error) {
	if err == nil {
		err = io.EOF
	}
	err = normalizeRemoteError(err)
	c.failOnce.Do(func() {
		c.mu.Lock()
		c.cause = err
		c.mu.Unlock()
		close(c.done)
		code := closeFailure
		var timeout net.Error
		switch {
		case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
			code = closeNormal
		case errors.Is(err, ErrAuthRejected):
			code = closeAuthRejected
		case errors.Is(err, ErrLimit):
			code = closeLimit
		case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, context.DeadlineExceeded):
			code = closeTimeout
		case errors.As(err, &timeout) && timeout.Timeout():
			code = closeTimeout
		case errors.Is(err, errControlProtocol):
			code = closeProtocol
		}
		_ = c.q.CloseWithError(code, "association closed")
	})
}

// RejectAuthentication carries an explicit authenticated-control failure in the
// QUIC close code. It remains observable if a preceding ERR stream write has
// not been transmitted when the association closes.
func (c *Conn) RejectAuthentication() { c.fail(ErrAuthRejected) }

// RejectLimit preserves BUSY/LIMIT when the control stream reply has not yet
// reached the peer at connection close. It never authorizes datagrams.
func (c *Conn) RejectLimit() { c.fail(ErrLimit) }

func (c *Conn) failure() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cause != nil {
		return c.cause
	}
	return net.ErrClosed
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closing = true
		if c.streamTimer != nil {
			c.streamTimer.Stop()
		}
		if c.writeTimer != nil {
			c.writeTimer.Stop()
		}
		c.mu.Unlock()
		c.fail(net.ErrClosed)
		c.streamStop()
		c.workers.Wait()
		for packet := range c.packets {
			packet.Release()
		}
		if c.cleanup != nil {
			c.cleanup()
		}
	})
	return nil
}

func (c *Conn) LocalAddr() net.Addr  { return c.q.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.q.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readUntil = t
	close(c.readChange)
	c.readChange = make(chan struct{})
	stream := c.stream
	if stream == nil {
		if c.streamTimer != nil {
			c.streamTimer.Stop()
		}
		if !t.IsZero() {
			c.streamTimer = time.AfterFunc(time.Until(t), func() {
				c.mu.Lock()
				expired := c.stream == nil && !c.readUntil.IsZero() && !time.Now().Before(c.readUntil)
				c.mu.Unlock()
				if expired {
					c.streamStop()
				}
			})
		}
	}
	c.mu.Unlock()
	if stream != nil {
		return stream.SetReadDeadline(t)
	}
	return nil
}

func (c *Conn) PreAuthDrops() uint64 { return c.preAuthDrops.Load() }

// DatagramAttrs are cumulative per-association events, not a network loss rate.
// Enqueued fragments have entered QUIC's send queue, without delivery proof.
func (c *Conn) DatagramAttrs() []any {
	return []any{
		"quic_pre_auth_drops", c.preAuthDrops.Load(),
		"quic_malformed_fragment_drops", c.malformedDrops.Load(),
		"quic_resource_drops", c.resourceDrops.Load(),
		"quic_fragment_limit_drops", c.fragmentLimitDrops.Load(),
		"quic_queue_full_drops", c.queueFullDrops.Load(),
		"quic_queue_expired_drops", c.queueExpiredDrops.Load(),
		"quic_incomplete_expired", c.incompleteExpired.Load(),
		"quic_received_fragments", c.fragmentReceives.Load(),
		"quic_enqueued_fragments", c.fragmentEnqueues.Load(),
	}
}
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeUntil = t
	c.armWriteTimerLocked()
	stream := c.stream
	c.mu.Unlock()
	if stream != nil {
		return stream.SetWriteDeadline(t)
	}
	return nil
}

func Dial(ctx context.Context, addr string, tlsConfig *tls.Config, resources *datagram.Resources, maxAge time.Duration, options ...DialOptions) (*Conn, error) {
	tokens, err := addressTokensFor(addr, tlsConfig, options)
	if err != nil {
		return nil, err
	}
	if resources == nil {
		resources = datagram.DefaultResources
	}
	reserve := 0
	if len(options) == 1 {
		reserve = options[0].SocketReserve
	}
	if !resources.AcquireSocketWithReserve(reserve) {
		return nil, datagram.ErrResourceLimit
	}
	release := true
	defer func() {
		if release {
			resources.ReleaseSocket()
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	// Resolve with the caller's context instead of net.ResolveUDPAddr's
	// unbounded background lookup. Both address families are supported.
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid QUIC address")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, fmt.Errorf("invalid QUIC port")
	}
	var addresses []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{ip}
	} else {
		addresses, err = net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
	}
	if len(addresses) == 0 {
		return nil, errors.New("QUIC address has no IP")
	}
	// Prefer the resolver's first address and one address of the other family.
	// A broken IPv6 route must not consume the entire handshake budget before
	// trying a usable IPv4 result. All attempts share the five-second deadline.
	if len(addresses) > 1 {
		for i := 1; i < len(addresses); i++ {
			if addresses[i].Is4() != addresses[0].Is4() {
				addresses[1], addresses[i] = addresses[i], addresses[1]
				break
			}
		}
	}
	addresses = addresses[:min(len(addresses), 4)]
	for i, ip := range addresses {
		attemptCtx := ctx
		attemptCancel := func() {}
		if i < len(addresses)-1 {
			attemptCtx, attemptCancel = context.WithTimeout(ctx, 2*time.Second)
		}
		remote := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(portNumber)))
		var conn *Conn
		conn, err = dialAddress(attemptCtx, remote, tlsConfig, resources, maxAge, tokens)
		attemptCancel()
		if err == nil {
			release = false
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, err
}

func dialAddress(ctx context.Context, remote *net.UDPAddr, tlsConfig *tls.Config, resources *datagram.Resources, maxAge time.Duration, tokens quic.TokenStore) (*Conn, error) {
	local := &net.UDPAddr{IP: net.IPv4zero}
	if remote.IP.To4() == nil {
		local.IP = net.IPv6unspecified
	}
	udp, err := net.ListenUDP("udp", local)
	if err != nil {
		return nil, err
	}
	tr := &quic.Transport{Conn: udp}
	cleanup := func() { _ = tr.Close(); _ = udp.Close(); resources.ReleaseSocket() }
	quicConfig := transportConfig()
	quicConfig.TokenStore = tokens
	q, err := tr.Dial(ctx, remote, tlsConfig, quicConfig)
	if err != nil {
		_ = tr.Close()
		_ = udp.Close()
		return nil, err
	}
	s, err := q.OpenStreamSync(ctx)
	if err != nil {
		_ = q.CloseWithError(1, "control unavailable")
		_ = tr.Close()
		_ = udp.Close()
		return nil, err
	}
	c, err := newConn(q, s, resources, maxAge, cleanup)
	if err != nil {
		_ = tr.Close()
		_ = udp.Close()
		return nil, err
	}
	return c, nil
}

type listener struct {
	ln        *quic.Listener
	tr        *quic.Transport
	udp       *net.UDPConn
	resources *datagram.Resources
	maxAge    time.Duration
	mu        sync.Mutex
	refs      int
	closed    bool
	once      sync.Once
	cleanOnce sync.Once
}

type handshakePermitKey struct{}

// Listen applies a transport-level connection cap before TLS handshakes, in
// addition to the application's shared admission limits after Accept.
func Listen(addr string, tlsConfig *tls.Config, resources *datagram.Resources, maxAge time.Duration, maxConnections int, maxHandshakes ...int) (net.Listener, error) {
	if maxConnections <= 0 {
		return nil, fmt.Errorf("QUIC connection limit must be positive")
	}
	handshakeLimit := min(maxConnections, 128)
	if len(maxHandshakes) > 1 || (len(maxHandshakes) == 1 && maxHandshakes[0] <= 0) {
		return nil, fmt.Errorf("invalid QUIC handshake limit")
	}
	if len(maxHandshakes) == 1 {
		handshakeLimit = min(maxConnections, maxHandshakes[0])
	}
	if resources == nil {
		resources = datagram.DefaultResources
	}
	if !resources.AcquireSocket() {
		return nil, datagram.ErrResourceLimit
	}
	bind, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		resources.ReleaseSocket()
		return nil, err
	}
	udp, err := net.ListenUDP("udp", bind)
	if err != nil {
		resources.ReleaseSocket()
		return nil, err
	}
	l := &listener{udp: udp, resources: resources, maxAge: maxAge}
	slots := make(chan struct{}, maxConnections)
	handshakes := make(chan struct{}, handshakeLimit)
	guard := ingress.NewGuard(8, 4, 16)
	l.tr = &quic.Transport{Conn: udp, VerifySourceAddress: func(net.Addr) bool { return true }}
	l.tr.ConnContext = func(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
		releasePeer, allowed := guard.Acquire(info.RemoteAddr)
		if !allowed {
			return nil, datagram.ErrResourceLimit
		}
		select {
		case slots <- struct{}{}:
		default:
			releasePeer()
			return nil, datagram.ErrResourceLimit
		}
		select {
		case handshakes <- struct{}{}:
		default:
			<-slots
			releasePeer()
			return nil, datagram.ErrResourceLimit
		}
		releaseHandshake := sync.OnceFunc(func() { <-handshakes; releasePeer() })
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			<-slots
			releaseHandshake()
			return nil, net.ErrClosed
		}
		l.refs++
		l.mu.Unlock()
		context.AfterFunc(ctx, func() {
			<-slots
			releaseHandshake()
			l.mu.Lock()
			l.refs--
			cleanup := l.closed && l.refs == 0
			l.mu.Unlock()
			if cleanup {
				l.cleanup()
			}
		})
		return context.WithValue(ctx, handshakePermitKey{}, releaseHandshake), nil
	}
	l.ln, err = l.tr.Listen(tlsConfig, transportConfig())
	if err != nil {
		_ = l.tr.Close()
		_ = udp.Close()
		resources.ReleaseSocket()
		return nil, err
	}
	return l, nil
}

func (l *listener) Accept() (net.Conn, error) {
	for {
		q, err := l.ln.Accept(context.Background())
		if err != nil {
			return nil, err
		}
		if release, ok := q.Context().Value(handshakePermitKey{}).(func()); ok {
			release()
		}
		c, err := newConn(q, nil, l.resources, l.maxAge, nil)
		if err == nil {
			return c, nil
		}
	}
}

func (l *listener) Addr() net.Addr { return l.ln.Addr() }
func (l *listener) Close() error {
	var err error
	l.once.Do(func() {
		err = l.ln.Close()
		// quic.Listener.Close leaves completed handshakes in its accept queue.
		// Drain and close those connections so none escape application shutdown.
		for {
			q, acceptErr := l.ln.Accept(context.Background())
			if acceptErr != nil {
				break
			}
			_ = q.CloseWithError(0, "listener closed")
		}
		l.mu.Lock()
		l.closed = true
		cleanup := l.refs == 0
		l.mu.Unlock()
		if cleanup {
			l.cleanup()
		}
	})
	return err
}
func (l *listener) cleanup() {
	l.cleanOnce.Do(func() { _ = l.tr.Close(); _ = l.udp.Close(); l.resources.ReleaseSocket() })
}
