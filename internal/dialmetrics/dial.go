// Package dialmetrics observes the standard dialer without replacing DNS or
// Happy Eyeballs. TCP is wall time from first connect attempt to dial return.
package dialmetrics

import (
	"context"
	"errors"
	"net"
	"net/http/httptrace"
	"sync"
	"time"
)

const dnsRetryDelay = 100 * time.Millisecond

type Timings struct {
	DNS, TCP   time.Duration
	DNSRetries int
}

func Dial(ctx context.Context, dialer *net.Dialer, network, address string) (net.Conn, Timings, error) {
	// Dialer.Timeout is otherwise restarted by each DialContext call. Keep the
	// original timeout/deadline as one budget for DNS, backoff and both attempts.
	deadline := dialer.Deadline
	if dialer.Timeout != 0 {
		timeout := time.Now().Add(dialer.Timeout)
		if deadline.IsZero() || timeout.Before(deadline) {
			deadline = timeout
		}
	}
	if !deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	return dialWith(ctx, dialer.DialContext, network, address)
}

type dialFunc func(context.Context, string, string) (net.Conn, error)

func dialWith(ctx context.Context, dial dialFunc, network, address string) (net.Conn, Timings, error) {
	var total Timings
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, total, err
		}
		if attempt > 0 {
			total.DNSRetries++
		}
		conn, timings, err := dialOnce(ctx, dial, network, address)
		total.DNS += timings.DNS
		total.TCP += timings.TCP
		if err == nil {
			return conn, total, nil
		}
		if attempt != 0 || !retryableDNS(err) || ctx.Err() != nil {
			return nil, total, err
		}
		timer := time.NewTimer(dnsRetryDelay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil, total, ctx.Err()
		case <-timer.C:
		}
	}
}

func retryableDNS(err error) bool {
	var dns *net.DNSError
	return errors.As(err, &dns) && !dns.IsNotFound && (dns.IsTimeout || dns.IsTemporary)
}

func dialOnce(ctx context.Context, dial dialFunc, network, address string) (net.Conn, Timings, error) {
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
	conn, err := dial(httptrace.WithClientTrace(ctx, trace), network, address)
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
