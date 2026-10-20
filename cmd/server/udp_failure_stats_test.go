package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"mygotunnel/internal/datagram"
	"mygotunnel/internal/socks5"
)

func TestUDPTargetDNSFailureIsCountedButCancellationIsNot(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if canceled {
			cancel()
		}
		queue := datagram.NewQueue(4, 65536, time.Second, nil)
		responses := datagram.NewQueue(4, 65536, time.Second, nil)
		target := &udpTarget{destination: socks5.UDPDatagram{Host: "missing.invalid", Port: 53}, pending: queue, cancel: cancel}
		var stats udpTargetFailures
		var up, down, dropped atomic.Uint64
		runUDPTarget(ctx, target, "missing.invalid:53", func(ctx context.Context, _, _ string) (net.Conn, error) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
		}, make(chan struct{}, 1), responses, &up, &down, &dropped, slog.New(slog.NewTextHandler(io.Discard, nil)), &stats)
		want := uint64(1)
		if canceled {
			want = 0
		}
		if stats.dial.Load() != want || stats.dns.Load() != want || !target.failed.Load() {
			t.Fatalf("canceled=%v dial=%d dns=%d", canceled, stats.dial.Load(), stats.dns.Load())
		}
		responses.Close()
		cancel()
	}
}
