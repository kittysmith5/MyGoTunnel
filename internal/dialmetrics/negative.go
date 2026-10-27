package dialmetrics

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type negativeKey struct {
	host, family string
	resolver     *net.Resolver
}
type NegativeStats struct {
	Hits, Stored uint64
	Entries      int
}

// NegativeCache preserves net.Dialer's DNS coalescing, Happy Eyeballs and error
// policy. Only definitive DNS-not-found results are retained; no connections,
// successful addresses, temporary failures or caller cancellations are cached.
type NegativeCache struct {
	mu           sync.Mutex
	entries      map[negativeKey]time.Time
	capacity     int
	ttl          time.Duration
	hits, stored uint64
	nextSweep    time.Time
	now          func() time.Time
}

func NewNegativeCache(capacity int, ttl time.Duration) *NegativeCache {
	if capacity <= 0 || ttl <= 0 {
		panic("invalid DNS negative cache limits")
	}
	return &NegativeCache{entries: make(map[negativeKey]time.Time), capacity: capacity, ttl: ttl, now: time.Now}
}
func cacheKey(d *net.Dialer, network, address string) (negativeKey, bool) {
	host, port, e := net.SplitHostPort(address)
	if e != nil || len(host) == 0 || len(host) > 253 {
		return negativeKey{}, false
	}
	p, e := strconv.Atoi(port)
	if e != nil || p < 1 || p > 65535 {
		return negativeKey{}, false
	}
	if net.ParseIP(host) != nil || strings.Contains(host, ":") {
		return negativeKey{}, false
	}
	family := "ip"
	switch network {
	case "tcp", "udp":
	case "tcp4", "udp4":
		family = "ip4"
	case "tcp6", "udp6":
		family = "ip6"
	default:
		return negativeKey{}, false
	}
	r := d.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	// Preserve trailing-dot/search-domain semantics and isolate resolver policy.
	return negativeKey{strings.ToLower(host), family, r}, true
}
func (c *NegativeCache) hit(key negativeKey) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	until, ok := c.entries[key]
	if ok && c.now().Before(until) {
		c.hits++
		return true
	}
	if ok {
		delete(c.entries, key)
	}
	return false
}
func (c *NegativeCache) store(key negativeKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	// A cohort of failed callers must not extend the first negative expiry.
	if until, ok := c.entries[key]; ok && now.Before(until) {
		return
	}
	if len(c.entries) >= c.capacity && !now.Before(c.nextSweep) {
		for k, until := range c.entries {
			if !now.Before(until) {
				delete(c.entries, k)
			}
		}
		c.nextSweep = now.Add(time.Second)
	}
	if len(c.entries) < c.capacity {
		c.entries[key] = now.Add(c.ttl)
		c.stored++
	}
}
func (c *NegativeCache) Dial(ctx context.Context, d *net.Dialer, network, address string) (net.Conn, Timings, error) {
	ctx, cancel := dialBudget(ctx, d)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, Timings{}, err
	}
	key, eligible := cacheKey(d, network, address)
	if c != nil && eligible && c.hit(key) {
		if err := ctx.Err(); err != nil {
			return nil, Timings{}, err
		}
		// Keep errors.As(*net.DNSError), the original target classification and
		// original address spelling. A hit has no fabricated DNS/TCP duration.
		host, _, _ := net.SplitHostPort(address)
		return nil, Timings{DNSNegativeHit: true}, &net.OpError{Op: "dial", Net: network, Err: &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}}
	}
	conn, t, err := dialWith(ctx, d.DialContext, network, address)
	var dns *net.DNSError
	if c != nil && eligible && ctx.Err() == nil && errors.As(err, &dns) && dns.IsNotFound && !dns.IsTimeout && !dns.IsTemporary {
		c.store(key)
	}
	return conn, t, err
}
func (c *NegativeCache) Stats() NegativeStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return NegativeStats{c.hits, c.stored, len(c.entries)}
}
