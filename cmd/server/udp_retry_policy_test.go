package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"mygotunnel/internal/config"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestUDPRetryTableBoundsCooldownAndClearsOnSuccess(t *testing.T) {
	table := newUDPRetryTable()
	now := time.Now()
	key := "owned-header"
	for i := 0; i < 12; i++ {
		table.failure(key, now)
		entry := table.entries[key]
		want := min(udpRetryInitial*time.Duration(1<<min(i, 4)), udpRetryMaximum)
		if entry.delay != want {
			t.Fatal(i, entry.delay, want)
		}
		if !table.blocked(key, now.Add(entry.delay-time.Nanosecond)) || table.blocked(key, now.Add(entry.delay)) {
			t.Fatal("cooldown boundary", i)
		}
		now = entry.until
	}
	table.success(key)
	if table.count() != 0 || table.blocked(key, now) {
		t.Fatal("success retained cooldown")
	}
	for i := 0; i < 1024; i++ {
		table.failure(fmt.Sprint(i), now.Add(time.Duration(i)))
		if table.count() > udpTargetLimit {
			t.Fatal("unbounded failed-key metadata")
		}
	}
	table.expire(now.Add(2 * udpRetryRetention))
	if table.count() != 0 {
		t.Fatal("expired failure keys retained")
	}
}
func TestUDPRetryIgnoresResourcesCancellationAndDuplicateErrors(t *testing.T) {
	for _, err := range []error{context.Canceled, net.ErrClosed, datagram.ErrResourceLimit, syscall.ENOBUFS, syscall.EMFILE, syscall.ENFILE, syscall.ENOMEM} {
		table := newUDPRetryTable()
		target := &udpTarget{key: "target", retries: table}
		target.recordFailure(err)
		if table.count() != 0 || target.failureRecorded.Load() {
			t.Fatal("non-target error entered cooldown", err)
		}
	}
	table := newUDPRetryTable()
	target := &udpTarget{key: "target", retries: table}
	err := &net.DNSError{IsNotFound: true, Err: "missing"}
	target.recordFailure(err)
	target.recordFailure(err)
	if table.entries["target"].delay != udpRetryInitial {
		t.Fatal("secondary target error doubled cooldown")
	}
}
func TestUDPRetrySuppressesStormAndRecoversInSameAssociation(t *testing.T) {
	resources := datagram.NewResources(20, 1<<20)
	defer resources.Close()
	dest, _ := udpIsolationEcho(t)
	address := net.JoinHostPort(dest.Host, strconv.Itoa(int(dest.Port)))
	var calls atomic.Int64
	var healthy atomic.Bool
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		calls.Add(1)
		if !healthy.Load() {
			return nil, &net.DNSError{Err: "controlled missing", IsNotFound: true}
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	a, b := net.Pipe()
	done := make(chan struct{})
	var logs bytes.Buffer
	go func() {
		defer close(done)
		defer a.Close()
		handleUDPTunnelWithDial(a, bufio.NewReader(a), slog.New(slog.NewTextHandler(&logs, nil)), time.Now(), 0, func() {}, config.UDPQueueConfig{}, dial, resources)
	}()
	defer func() { b.Close(); <-done }()
	b.SetDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(b)
	if _, err := tunnel.ReadLine(reader); err != nil {
		t.Fatal(err)
	}
	packet := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "missing.invalid", Port: 53}, []byte("recover"))
	send := func() {
		t.Helper()
		if err := tunnel.WriteDatagram(b, packet); err != nil {
			t.Fatal(err)
		}
	}
	waitCalls := func(want int64) {
		t.Helper()
		until := time.Now().Add(time.Second)
		for calls.Load() != want && time.Now().Before(until) {
			time.Sleep(time.Millisecond)
		}
		if calls.Load() != want {
			t.Fatal(calls.Load(), want)
		}
		waitUDPRecoverySockets(t, resources, 0)
	}
	send()
	waitCalls(1)
	for i := 0; i < 19; i++ {
		send()
		time.Sleep(time.Millisecond)
	}
	time.Sleep(10 * time.Millisecond)
	t.Logf("20 paced datagrams caused %d dial attempts", calls.Load())
	if calls.Load() != 1 {
		t.Fatal("failure storm bypassed cooldown", calls.Load())
	}
	time.Sleep(udpRetryInitial)
	send()
	waitCalls(2)
	healthy.Store(true)
	time.Sleep(2*udpRetryInitial + 10*time.Millisecond)
	send()
	if got, err := tunnel.ReadDatagram(reader); err != nil || !bytes.Equal(got, packet) {
		t.Fatal("target did not recover after bounded cooldown", err)
	}
	if calls.Load() != 3 {
		t.Fatal(calls.Load())
	}
	b.Close()
	<-done
	if text := logs.String(); !strings.Contains(text, "target_backoff_drops=19") || !strings.Contains(text, "target_backoff_entries=0") {
		t.Fatal(text)
	}
}

func TestUDPRetryOlderAttemptsCannotEraseOrOverwriteNewFailure(t *testing.T) {
	table := newUDPRetryTable()
	now := time.Now()
	oldCtx, cancel := context.WithCancel(context.Background())
	old := &udpTarget{key: "same-target", retries: table, retryGeneration: 1, retryContext: oldCtx}
	newer := &udpTarget{key: "same-target", retries: table, retryGeneration: 2, retryContext: context.Background()}
	table.failureAttempt(newer, now)
	first := table.entries[newer.key]
	// Even before observing cancellation, an older generation cannot alter the
	// newer record. A canceled old worker also cannot resurrect a cleared key.
	table.successAttempt(old)
	table.failureAttempt(old, now.Add(time.Millisecond))
	if got := table.entries[newer.key]; got != first {
		t.Fatal("older generation changed new failure", got, first)
	}
	cancel()
	table.successAttempt(old)
	table.failureAttempt(old, now.Add(time.Millisecond))
	if got := table.entries[newer.key]; got != first {
		t.Fatal("canceled old worker changed new failure", got, first)
	}
	table.successAttempt(newer)
	if table.count() != 0 {
		t.Fatal("current healthy attempt did not clear old history")
	}
	table.failureAttempt(old, now.Add(2*time.Millisecond))
	if table.count() != 0 {
		t.Fatal("canceled old failure resurrected stale history")
	}
	// A first successful reply must not clear an already recorded failure in the
	// same attempt, even if read and write goroutines race around cancellation.
	newer.recordFailure(syscall.ECONNREFUSED)
	table.successAttempt(newer)
	if !table.blocked(newer.key, time.Now()) {
		t.Fatal("same attempt success erased its root failure")
	}
}
func TestUDPRetryCanceledReaderPreservesNewAttemptFailure(t *testing.T) {
	resources := datagram.NewResources(1, 1<<20)
	defer resources.Close()
	responses := datagram.NewQueue(4, 65000, time.Second, nil, resources)
	defer responses.Close()
	table := newUDPRetryTable()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	old := &udpTarget{key: "same-target", retries: table, retryGeneration: 1, retryContext: ctx, destination: socks5.UDPDatagram{Host: "127.0.0.1", Port: 53}, conn: &udpBurstReplyConn{payload: []byte("late-reply"), remaining: 1, closed: make(chan struct{}), exhausted: make(chan struct{})}}
	newer := &udpTarget{key: old.key, retries: table, retryGeneration: 2, retryContext: context.Background()}
	table.failureAttempt(newer, time.Now())
	var up, down atomic.Uint64
	readUDPResponses(old, responses, ctx.Done(), &up, &down, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !table.blocked(old.key, time.Now()) || table.entries[old.key].generation != 2 || responses.Stats().Packets != 0 {
		t.Fatal("late canceled read cleared newer cooldown or queued reply", table.entries, responses.Stats())
	}
}
