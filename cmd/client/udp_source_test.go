package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"mygotunnel/internal/datagram"
	"mygotunnel/internal/socks5"
)

func TestResolveUDPAssociateSource(t *testing.T) {
	for _, tc := range []struct {
		name, source, peer string
		wantIPs            []string
		addresses          []net.IPAddr
		lookupErr          error
		rep                byte
		lookups            int
	}{
		{name: "empty wildcard uses TCP peer", peer: "127.0.0.1", wantIPs: []string{"127.0.0.1"}},
		{name: "IPv4 wildcard uses TCP peer", source: "0.0.0.0", peer: "127.0.0.1", wantIPs: []string{"127.0.0.1"}},
		{name: "IPv6 wildcard uses TCP peer", source: "::", peer: "::1", wantIPs: []string{"::1"}},
		{name: "explicit IPv4 may differ from TCP peer", source: "127.0.0.2", peer: "127.0.0.1", wantIPs: []string{"127.0.0.2"}},
		{name: "explicit IPv6", source: "0:0:0:0:0:0:0:1", peer: "::2", wantIPs: []string{"::1"}},
		{name: "mapped IPv4", source: "::ffff:127.0.0.1", peer: "127.0.0.2", wantIPs: []string{"127.0.0.1"}},
		{name: "domain resolves expected UDP endpoints", source: "source.test", peer: "127.0.0.1", wantIPs: []string{"::1", "127.0.0.2"}, addresses: []net.IPAddr{{IP: net.ParseIP("::1")}, {IP: net.ParseIP("127.0.0.2")}}, lookups: 1},
		{name: "empty resolution", source: "missing.test", peer: "127.0.0.1", rep: 2, lookups: 1},
		{name: "DNS failure", source: "missing.test", peer: "127.0.0.1", lookupErr: &net.DNSError{Err: "no such host", IsNotFound: true}, rep: 4, lookups: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			allowed, rep, err := resolveUDPAssociateSource(context.Background(), tc.source, net.ParseIP(tc.peer), func(_ context.Context, host string) ([]net.IPAddr, error) {
				calls++
				if host != tc.source {
					t.Errorf("resolved %q instead of source %q", host, tc.source)
				}
				return tc.addresses, tc.lookupErr
			})
			if rep != tc.rep || (err != nil) != (tc.rep != 0) || calls != tc.lookups {
				t.Fatalf("rep=%d error=%v lookups=%d; want rep=%d lookups=%d", rep, err, calls, tc.rep, tc.lookups)
			}
			if len(allowed) != len(tc.wantIPs) {
				t.Fatalf("allowed source IPs = %v, want %v", allowed, tc.wantIPs)
			}
			for i, want := range tc.wantIPs {
				if !allowed[i].Equal(net.ParseIP(want)) {
					t.Fatalf("allowed source IP %d = %v, want %s", i, allowed[i], want)
				}
			}
		})
	}
}

func TestUDPAssociateSourceLookupHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, rep, err := resolveUDPAssociateSource(ctx, "source.test", net.ParseIP("127.0.0.1"), func(lookupCtx context.Context, _ string) ([]net.IPAddr, error) {
		<-lookupCtx.Done()
		return nil, lookupCtx.Err()
	})
	if rep != 4 || !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatalf("source lookup cancellation: rep=%d error=%v duration=%v", rep, err, time.Since(started))
	}
}

func TestUDPAssociationUsesDeclaredSourceDomainAndResolvesItOnce(t *testing.T) {
	var calls atomic.Int32
	session := newUDPAssociationTestReply(t, socks5.Request{Command: 3, Address: "localhost"}, 0, func(ctx context.Context, host string) ([]net.IPAddr, error) {
		calls.Add(1)
		if host != "localhost" {
			t.Errorf("source lookup host = %q", host)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > socks5Timeout || time.Until(deadline) <= 0 {
			t.Errorf("source lookup has no bounded setup deadline: %v", deadline)
		}
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.2")}}, nil
	})
	foreign := testUDPSocket(t, "127.0.0.3")
	sender := testUDPSocket(t, "127.0.0.2")
	packet := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "target.test", Port: 53}, nil)
	if _, err := foreign.WriteToUDP(packet, session.relay); err != nil {
		t.Fatal(err)
	}
	_ = foreign.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := foreign.ReadFromUDP(make([]byte, 100)); err == nil {
		t.Fatal("source domain authorized an address outside its resolved endpoint set")
	}
	for _, payload := range [][]byte{nil, []byte("domain target")} {
		packet = socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "target.test", Port: 53}, payload)
		if _, err := sender.WriteToUDP(packet, session.relay); err != nil {
			t.Fatal(err)
		}
		_ = sender.SetReadDeadline(time.Now().Add(time.Second))
		buffer := make([]byte, 100)
		n, _, err := sender.ReadFromUDP(buffer)
		if err != nil || !bytes.Equal(buffer[:n], packet) {
			t.Fatalf("domain source/target and zero payload forwarding failed: %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("source resolved %d times, want one setup lookup", got)
	}
}

func TestUDPAssociationRejectsSourceBeforeOpeningRemote(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		addresses    []net.IPAddr
		lookupErr    error
		rep          byte
	}{
		{name: "DNS failure", source: "missing.test", lookupErr: &net.DNSError{Err: "no such host", IsNotFound: true}, rep: 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resources := datagram.NewResources(1, 1<<20)
			defer resources.Close()
			newUDPAssociationTestReply(t, socks5.Request{Command: 3, Address: tc.source}, tc.rep, func(context.Context, string) ([]net.IPAddr, error) {
				return tc.addresses, tc.lookupErr
			}, resources)
			if s := resources.Stats(); s.Sockets != 0 || s.PeakBytes != 0 {
				t.Fatalf("invalid source reserved UDP resources: %+v", s)
			}
		})
	}
}
