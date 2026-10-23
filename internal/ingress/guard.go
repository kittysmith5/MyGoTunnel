// Package ingress provides a bounded HTTPS fallback for the legacy tunnel.
package ingress

import (
	"net"
	"sync"
	"time"

	"mygotunnel/internal/authlimit"
)

type peer struct {
	active int
	tokens float64
	last   time.Time
}

// Guard has a separate bounded table from the credential failure limiter.
type Guard struct {
	mu                                sync.Mutex
	peers                             map[string]*peer
	concurrent, rate, burst, maxPeers int
	nextSweep                         time.Time
	now                               func() time.Time
}

func NewGuard(concurrent, rate, burst int) *Guard {
	return &Guard{peers: make(map[string]*peer), concurrent: concurrent, rate: rate, burst: burst, maxPeers: 4096, now: time.Now}
}

func (g *Guard) Acquire(addr net.Addr) (func(), bool) {
	key := authlimit.PeerKey(addr)
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	p := g.peers[key]
	if p == nil {
		if len(g.peers) >= g.maxPeers && !now.Before(g.nextSweep) {
			for k, old := range g.peers {
				if old.active == 0 && now.Sub(old.last) >= time.Minute {
					delete(g.peers, k)
				}
			}
			g.nextSweep = now.Add(time.Second)
		}
		if len(g.peers) >= g.maxPeers {
			return nil, false
		}
		p = &peer{tokens: float64(g.burst), last: now}
		g.peers[key] = p
	}
	p.tokens = min(float64(g.burst), p.tokens+max(0, now.Sub(p.last).Seconds())*float64(g.rate))
	p.last = now
	if p.tokens < 1 {
		return nil, false
	}
	p.tokens-- // Charge accepted TCP attempts even when the concurrency cap rejects.
	if p.active >= g.concurrent {
		return nil, false
	}
	p.active++
	return sync.OnceFunc(func() {
		g.mu.Lock()
		p.active--
		g.mu.Unlock()
	}), true
}
