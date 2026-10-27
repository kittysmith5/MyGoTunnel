package dialmetrics

import (
	"context"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type dnsFixture struct {
	r     *net.Resolver
	calls atomic.Int32
	code  atomic.Int32
}

func newDNSFixture(t *testing.T) *dnsFixture {
	t.Helper()
	f := &dnsFixture{}
	f.code.Store(int32(dnsmessage.RCodeNameError))
	u, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, addr, e := u.ReadFromUDP(buf)
			if e != nil {
				return
			}
			f.calls.Add(1)
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil {
				continue
			}
			time.Sleep(15 * time.Millisecond)
			answer := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, Authoritative: true, RecursionDesired: true, RecursionAvailable: true, RCode: dnsmessage.RCode(f.code.Load())}, Questions: q.Questions}
			if answer.RCode == dnsmessage.RCodeSuccess {
				for _, question := range q.Questions {
					if question.Type == dnsmessage.TypeA {
						answer.Answers = append(answer.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}})
					}
				}
			}
			wire, e := answer.Pack()
			if e == nil {
				_, _ = u.WriteToUDP(wire, addr)
			}
		}
	}()
	t.Cleanup(func() { u.Close(); <-done })
	f.r = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp4", u.LocalAddr().String())
	}}
	return f
}
func TestNegativeCacheCoalescesResolverAndRecoversAfterExpiry(t *testing.T) {
	f := newDNSFixture(t)
	cache := NewNegativeCache(4, 10*time.Second)
	d := &net.Dialer{Resolver: f.r, Timeout: time.Second}
	var wg sync.WaitGroup
	var failures atomic.Int32
	start := make(chan struct{})
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			c, _, err := cache.Dial(context.Background(), d, "tcp4", "missing.invalid.:443")
			if c != nil {
				c.Close()
				failures.Add(1)
			}
			var dns *net.DNSError
			if !errors.As(err, &dns) || !dns.IsNotFound {
				failures.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if failures.Load() != 0 || f.calls.Load() != 1 {
		t.Fatal("resolver coalescing", failures.Load(), f.calls.Load())
	}
	_, timings, err := cache.Dial(context.Background(), d, "udp4", "missing.invalid.:53")
	var dns *net.DNSError
	if !errors.As(err, &dns) || !dns.IsNotFound || !timings.DNSNegativeHit || timings.DNS != 0 || f.calls.Load() != 1 {
		t.Fatal("negative result not shared across target ports/transports", err, timings, f.calls.Load())
	}
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		c, e := listener.Accept()
		if e == nil {
			c.Close()
		}
	}()
	cache.mu.Lock()
	for k := range cache.entries {
		cache.entries[k] = time.Now().Add(-time.Second)
	}
	cache.mu.Unlock()
	f.code.Store(int32(dnsmessage.RCodeSuccess))
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	c, timing, e := cache.Dial(context.Background(), d, "tcp4", net.JoinHostPort("missing.invalid.", port))
	if e != nil {
		t.Fatal("negative entry hid recovery", e)
	}
	c.Close()
	<-accepted
	if timing.DNSNegativeHit || f.calls.Load() != 2 {
		t.Fatal(timing, f.calls.Load())
	}
	t.Logf("32 concurrent missing-target requests: DNS queries=1; cached repeat=0; expired entry resolved successfully")
}
func TestNegativeCacheNeverStoresTemporaryFailureAndSeparatesResolvers(t *testing.T) {
	f := newDNSFixture(t)
	f.code.Store(int32(dnsmessage.RCodeServerFailure))
	c := NewNegativeCache(4, time.Second)
	d := &net.Dialer{Resolver: f.r, Timeout: time.Second}
	for range 2 {
		_, _, err := c.Dial(context.Background(), d, "tcp4", "temporary.invalid.:443")
		if err == nil {
			t.Fatal("fixture unexpectedly succeeded")
		}
	}
	if c.Stats().Entries != 0 || c.Stats().Hits != 0 {
		t.Fatal("cached temporary DNS", c.Stats())
	}
	f.code.Store(int32(dnsmessage.RCodeNameError))
	_, _, _ = c.Dial(context.Background(), d, "tcp4", "missing.invalid.:443")
	calls := f.calls.Load()
	second := &net.Dialer{Resolver: &net.Resolver{PreferGo: true, Dial: f.r.Dial}, Timeout: time.Second}
	_, tm, _ := c.Dial(context.Background(), second, "tcp4", "missing.invalid.:443")
	if tm.DNSNegativeHit || f.calls.Load() == calls {
		t.Fatal("mixed resolver policies")
	}
}
func TestNegativeCacheBoundAndDeadlinePrecedence(t *testing.T) {
	c := NewNegativeCache(2, time.Second)
	now := time.Now()
	c.now = func() time.Time { return now }
	a := negativeKey{host: "a.invalid"}
	b := negativeKey{host: "b.invalid"}
	x := negativeKey{host: "c.invalid"}
	c.store(a)
	c.store(b)
	c.store(x)
	if c.Stats().Entries != 2 {
		t.Fatal("unbounded cache")
	}
	now = now.Add(time.Second)
	c.store(x)
	if c.Stats().Entries != 1 || c.hit(a) {
		t.Fatal("expired entries not swept")
	}
	d := &net.Dialer{Deadline: time.Now().Add(-time.Second)}
	key, _ := cacheKey(d, "tcp", "missing.invalid:443")
	c.store(key)
	_, tm, err := c.Dial(context.Background(), d, "tcp", "missing.invalid:443")
	if !errors.Is(err, context.DeadlineExceeded) || tm.DNSNegativeHit {
		t.Fatal("cache overrode dial budget", err, tm)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = c.Dial(ctx, &net.Dialer{}, "tcp", "missing.invalid:443")
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
