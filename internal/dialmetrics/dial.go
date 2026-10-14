// Package dialmetrics observes the standard dialer without replacing DNS or
// Happy Eyeballs. TCP is wall time from first connect attempt to dial return.
package dialmetrics

import (
	"context"
	"net"
	"net/http/httptrace"
	"sync"
	"time"
)

type Timings struct{ DNS, TCP time.Duration }

func Dial(ctx context.Context, dialer *net.Dialer, network, address string) (net.Conn, Timings, error) {
	var mu sync.Mutex
	var dnsStart, tcpStart time.Time
	var dns time.Duration
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { mu.Lock(); dnsStart = time.Now(); mu.Unlock() },
		DNSDone: func(httptrace.DNSDoneInfo) {
			mu.Lock()
			if !dnsStart.IsZero() {
				dns += time.Since(dnsStart)
				dnsStart = time.Time{}
			}
			mu.Unlock()
		},
		ConnectStart: func(_, _ string) {
			mu.Lock()
			if tcpStart.IsZero() {
				tcpStart = time.Now()
			}
			mu.Unlock()
		},
	}
	conn, err := dialer.DialContext(httptrace.WithClientTrace(ctx, trace), network, address)
	now := time.Now()
	mu.Lock()
	result := Timings{DNS: dns}
	if !dnsStart.IsZero() {
		result.DNS += now.Sub(dnsStart)
	}
	if !tcpStart.IsZero() {
		result.TCP = now.Sub(tcpStart)
	}
	mu.Unlock()
	return conn, result, err
}
