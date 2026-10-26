package quicstream

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/ingress"
)

type handshakeKey struct{}
type Listener struct {
	ln                      *quic.Listener
	tr                      *quic.Transport
	udp                     *net.UDPConn
	resources               *datagram.Resources
	ctx                     context.Context
	cancel                  context.CancelFunc
	incoming                chan net.Conn
	done                    chan struct{}
	closeOnce, shutdownOnce sync.Once
	wg                      sync.WaitGroup
	mu                      sync.Mutex
	peers                   map[*quic.Conn]struct{}
	err                     error
	closedAt                time.Time
}

func Listen(addr string, config *tls.Config, resources *datagram.Resources, maxConnections, maxSetup int) (*Listener, error) {
	if maxConnections <= 0 || maxSetup <= 0 {
		return nil, errors.New("invalid QUIC TCP limits")
	}
	if resources == nil {
		resources = datagram.DefaultResources
	}
	if !resources.AcquireSocket() {
		return nil, datagram.ErrResourceLimit
	}
	address, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		resources.ReleaseSocket()
		return nil, err
	}
	udp, err := net.ListenUDP("udp", address)
	if err != nil {
		resources.ReleaseSocket()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &Listener{udp: udp, resources: resources, ctx: ctx, cancel: cancel, incoming: make(chan net.Conn), done: make(chan struct{}), peers: make(map[*quic.Conn]struct{})}
	l.tr = &quic.Transport{Conn: udp, VerifySourceAddress: func(net.Addr) bool { return true }}
	slots := make(chan struct{}, min(32, maxConnections))
	handshakes := make(chan struct{}, min(32, maxSetup))
	guard := ingress.NewGuard(8, 4, 16)
	l.tr.ConnContext = func(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
		release, ok := guard.Acquire(info.RemoteAddr)
		if !ok {
			return nil, datagram.ErrResourceLimit
		}
		select {
		case slots <- struct{}{}:
		default:
			release()
			return nil, datagram.ErrResourceLimit
		}
		select {
		case handshakes <- struct{}{}:
		default:
			<-slots
			release()
			return nil, datagram.ErrResourceLimit
		}
		finish := sync.OnceFunc(func() { <-handshakes; release() })
		context.AfterFunc(ctx, func() { finish(); <-slots })
		return context.WithValue(ctx, handshakeKey{}, finish), nil
	}
	l.ln, err = l.tr.Listen(config, transportConfig())
	if err != nil {
		cancel()
		_ = l.tr.Close()
		_ = udp.Close()
		resources.ReleaseSocket()
		return nil, err
	}
	l.wg.Add(1)
	go l.acceptConnections()
	return l, nil
}
func (l *Listener) acceptConnections() {
	defer l.wg.Done()
	for {
		q, err := l.ln.Accept(l.ctx)
		if err != nil {
			l.mu.Lock()
			l.err = err
			l.mu.Unlock()
			l.Close()
			return
		}
		if f, ok := q.Context().Value(handshakeKey{}).(func()); ok {
			f()
		}
		l.mu.Lock()
		if !l.closedAt.IsZero() {
			l.mu.Unlock()
			_ = q.CloseWithError(0, "listener stopped")
			continue
		}
		l.peers[q] = struct{}{}
		l.mu.Unlock()
		l.wg.Add(1)
		go l.acceptStreams(q)
	}
}
func (l *Listener) acceptStreams(q *quic.Conn) {
	defer l.wg.Done()
	authTimer := time.AfterFunc(5*time.Second, func() { _ = q.CloseWithError(0x101, "authentication timeout") })
	authorize := sync.OnceFunc(func() { authTimer.Stop() })
	context.AfterFunc(q.Context(), func() { authTimer.Stop(); l.mu.Lock(); delete(l.peers, q); l.mu.Unlock() })
	for {
		s, err := q.AcceptStream(l.ctx)
		if err != nil {
			return
		}
		conn := &Stream{q: q, s: s, authorize: authorize}
		select {
		case l.incoming <- conn:
		case <-l.done:
			_ = conn.Close()
			return
		case <-q.Context().Done():
			_ = conn.Close()
			return
		}
	}
}
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.incoming:
		return c, nil
	case <-l.done:
		l.mu.Lock()
		e := l.err
		l.mu.Unlock()
		if e == nil {
			e = net.ErrClosed
		}
		return nil, e
	}
}
func (l *Listener) Addr() net.Addr { return l.udp.LocalAddr() }

// Close stops accepting streams. It deliberately retains accepted transports
// so admission's normal half-close/drain grace can finish existing handlers.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.closedAt = time.Now()
		l.mu.Unlock()
		close(l.done)
		l.cancel()
		_ = l.ln.Close()
	})
	return nil
}

// Retain the UDP transport through the configured drain window even when the
// last handler finished first: QUIC CloseWrite enqueues a FIN, unlike TCP kernel
// socket teardown. Grace expiry still force-closes all remaining transports.
func (l *Listener) Shutdown(grace time.Duration) {
	l.Close()
	l.shutdownOnce.Do(func() {
		l.mu.Lock()
		at := l.closedAt
		l.mu.Unlock()
		if left := grace - time.Since(at); left > 0 {
			time.Sleep(left)
		}
		l.mu.Lock()
		peers := make([]*quic.Conn, 0, len(l.peers))
		for q := range l.peers {
			peers = append(peers, q)
		}
		l.mu.Unlock()
		for _, q := range peers {
			_ = q.CloseWithError(0, "server stopped")
		}
		_ = l.tr.Close()
		_ = l.udp.Close()
		l.wg.Wait()
		l.resources.ReleaseSocket()
	})
}
