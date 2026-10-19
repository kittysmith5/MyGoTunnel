package dialmetrics

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestDialTimings(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()
	for _, host := range []string{"127.0.0.1", "localhost"} {
		_, port, _ := net.SplitHostPort(l.Addr().String())
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		c, m, e := Dial(ctx, &net.Dialer{}, "tcp", net.JoinHostPort(host, port))
		cancel()
		if e != nil {
			t.Fatal(e)
		}
		c.Close()
		if m.TCP <= 0 {
			t.Fatal(m)
		}
		if host == "127.0.0.1" && m.DNS != 0 {
			t.Fatal("literal IP triggered DNS")
		}
		if host == "localhost" && m.DNS <= 0 {
			t.Fatal("DNS not observed")
		}
	}
	l.Close()
	<-done
}

func TestDialRetriesTemporaryDNSFailureOnce(t *testing.T) {
	wantConn, peer := net.Pipe()
	defer wantConn.Close()
	defer peer.Close()
	var calls int
	conn, timings, err := dialWith(context.Background(), func(context.Context, string, string) (net.Conn, error) {
		calls++
		if calls == 1 {
			return nil, &net.DNSError{Err: "temporary resolver failure", Name: "target.invalid", IsTemporary: true}
		}
		return wantConn, nil
	}, "tcp", "target.invalid:443")
	if err != nil || conn != wantConn {
		t.Fatalf("retry dial = %v, %v", conn, err)
	}
	if calls != 2 || timings.DNSRetries != 1 {
		t.Fatalf("calls=%d timings=%+v, want one retry", calls, timings)
	}
}

func TestDialDoesNotRetryNotFoundDNSFailure(t *testing.T) {
	var calls int
	_, timings, err := dialWith(context.Background(), func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, &net.DNSError{Err: "no such host", Name: "missing.invalid", IsNotFound: true}
	}, "tcp", "missing.invalid:443")
	if err == nil || calls != 1 || timings.DNSRetries != 0 {
		t.Fatalf("calls=%d timings=%+v error=%v, want no retry", calls, timings, err)
	}
}

func TestDialDNSRetryHonorsContextDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	var calls int
	_, timings, err := dialWith(ctx, func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, &net.DNSError{Err: "temporary resolver failure", IsTemporary: true}
	}, "tcp", "target.invalid:443")
	if !errors.Is(err, context.DeadlineExceeded) || calls != 1 || timings.DNSRetries != 1 {
		t.Fatalf("calls=%d timings=%+v error=%v, retry did not honor context", calls, timings, err)
	}
}
