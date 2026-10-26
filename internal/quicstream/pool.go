package quicstream

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"mygotunnel/internal/datagram"
)

var ErrBusy = errors.New("QUIC TCP stream capacity reached")

type Timings struct {
	DNS, Handshake time.Duration
	Reused         bool
}
type physical struct {
	q       *quic.Conn
	tr      *quic.Transport
	udp     *net.UDPConn
	active  int
	cleanup func()
}

// Pool holds at most two physical connections and 64 streams on each. Setup is
// serialized with a context-aware gate. Existing business streams are never replayed.
type Pool struct {
	ctx              context.Context
	cancel           context.CancelFunc
	gate             chan struct{}
	mu               sync.Mutex
	addr             string
	tls              *tls.Config
	resources        *datagram.Resources
	peers            []*physical
	closed, draining bool
	drainAt          time.Time
}

func NewPool(addr string, config *tls.Config, resources *datagram.Resources) *Pool {
	if resources == nil {
		resources = datagram.DefaultResources
	}
	c := config.Clone()
	c.NextProtos = []string{ALPN}
	c.ClientSessionCache = nil
	ctx, cancel := context.WithCancel(context.Background())
	return &Pool{ctx: ctx, cancel: cancel, gate: make(chan struct{}, 1), addr: addr, tls: c, resources: resources}
}
func (p *Pool) Open(ctx context.Context) (net.Conn, Timings, error) {
	var timings Timings
	select {
	case p.gate <- struct{}{}:
	case <-p.ctx.Done():
		return nil, timings, net.ErrClosed
	case <-ctx.Done():
		return nil, timings, ctx.Err()
	}
	defer func() { <-p.gate }()
	if err := ctx.Err(); err != nil {
		return nil, timings, err
	}
	p.mu.Lock()
	if p.closed || p.draining {
		p.mu.Unlock()
		return nil, timings, net.ErrClosed
	}
	live := p.peers[:0]
	for _, peer := range p.peers {
		if peer.q.Context().Err() == nil {
			live = append(live, peer)
		}
	}
	p.peers = live
	var selected *physical
	for _, peer := range p.peers {
		if selected == nil || peer.active < selected.active {
			selected = peer
		}
	}
	need := selected == nil || (selected.active > 0 && len(p.peers) < 2)
	p.mu.Unlock()
	if need {
		peer, t, e := p.dial(ctx)
		timings = t
		if e != nil {
			if selected == nil || !errors.Is(e, datagram.ErrResourceLimit) {
				return nil, timings, e
			}
			// A scarce socket budget must not prevent using a live validated connection.
			timings.Reused = true
		} else {
			p.mu.Lock()
			if p.closed || p.draining {
				p.mu.Unlock()
				peer.cleanup()
				return nil, timings, net.ErrClosed
			}
			p.peers = append(p.peers, peer)
			selected = peer
			p.mu.Unlock()
		}
	} else {
		timings.Reused = true
	}

	p.mu.Lock()
	if p.closed || p.draining {
		p.mu.Unlock()
		return nil, timings, net.ErrClosed
	}
	if selected.active >= streamLimit {
		p.mu.Unlock()
		return nil, timings, ErrBusy
	}
	// Try each live connection; stream credits can lag local Close until peer ACKs.
	peers := append([]*physical{selected}, p.peers...)
	var lastError error
	for _, peer := range peers {
		if peer.q.Context().Err() != nil {
			lastError = context.Cause(peer.q.Context())
			continue
		}
		if peer.active >= streamLimit {
			continue
		}
		s, e := peer.q.OpenStream()
		if e != nil {
			var capacity *quic.StreamLimitReachedError
			if !errors.As(e, &capacity) {
				lastError = e
			}
			continue
		}
		peer.active++
		p.mu.Unlock()
		return &Stream{q: peer.q, s: s, release: func() { p.mu.Lock(); peer.active--; p.mu.Unlock() }}, timings, nil
	}
	p.mu.Unlock()
	if lastError != nil {
		return nil, timings, lastError
	}
	return nil, timings, ErrBusy
}
func (p *Pool) dial(parent context.Context) (*physical, Timings, error) {
	var t Timings
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	stopPool := context.AfterFunc(p.ctx, cancel)
	defer stopPool()
	host, port, e := net.SplitHostPort(p.addr)
	if e != nil {
		return nil, t, e
	}
	var ips []netip.Addr
	if ip, e := netip.ParseAddr(host); e == nil {
		ips = []netip.Addr{ip}
	} else {
		start := time.Now()
		ips, e = net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		t.DNS = time.Since(start)
		if e != nil {
			return nil, t, e
		}
	}
	if len(ips) == 0 {
		return nil, t, errors.New("QUIC TCP endpoint has no IP")
	}
	// Bound address attempts and let an alternate family run within the same budget.
	for i := 1; i < len(ips); i++ {
		if ips[i].Is4() != ips[0].Is4() {
			ips[1], ips[i] = ips[i], ips[1]
			break
		}
	}
	ips = ips[:min(2, len(ips))]
	var last error
	for i, ip := range ips {
		if !p.resources.AcquireSocket() {
			return nil, t, datagram.ErrResourceLimit
		}
		network := "udp6"
		if ip.Is4() {
			network = "udp4"
		}
		udp, err := net.ListenUDP(network, nil)
		if err != nil {
			p.resources.ReleaseSocket()
			return nil, t, err
		}
		tr := &quic.Transport{Conn: udp}
		cleanup := sync.OnceFunc(func() { _ = tr.Close(); _ = udp.Close(); p.resources.ReleaseSocket() })
		attempt := ctx
		stop := func() {}
		if i == 0 && len(ips) > 1 {
			attempt, stop = context.WithTimeout(ctx, 2500*time.Millisecond)
		}
		remote, err := net.ResolveUDPAddr(network, net.JoinHostPort(ip.String(), port))
		if err != nil {
			stop()
			cleanup()
			return nil, t, err
		}
		start := time.Now()
		q, err := tr.Dial(attempt, remote, p.tls, transportConfig())
		t.Handshake += time.Since(start)
		stop()
		if err == nil {
			peer := &physical{q: q, tr: tr, udp: udp, cleanup: cleanup}
			context.AfterFunc(q.Context(), cleanup)
			return peer, t, nil
		}
		cleanup()
		last = err
		// Trust errors must not trigger alternate-address retries.
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			return nil, t, err
		}
	}
	return nil, t, last
}
func (p *Pool) Drain() {
	p.mu.Lock()
	p.draining = true
	if p.drainAt.IsZero() {
		p.drainAt = time.Now()
	}
	p.mu.Unlock()
}
func (p *Pool) Close() {
	p.cancel()
	p.mu.Lock()
	p.closed = true
	peers := append([]*physical(nil), p.peers...)
	p.mu.Unlock()
	for _, peer := range peers {
		_ = peer.q.CloseWithError(0, "client stopped")
		peer.cleanup()
	}
	// A dial already in progress must observe closed and clean its socket too.
	p.gate <- struct{}{}
	<-p.gate
}
func (p *Pool) CloseAfterGrace(grace time.Duration) {
	p.mu.Lock()
	at := p.drainAt
	p.mu.Unlock()
	if !at.IsZero() {
		if left := grace - time.Since(at); left > 0 {
			time.Sleep(left)
		}
	}
	p.Close()
}

func (p *Pool) Stats() (connections, streams int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, peer := range p.peers {
		if peer.q.Context().Err() == nil {
			connections++
			streams += peer.active
		}
	}
	return
}
