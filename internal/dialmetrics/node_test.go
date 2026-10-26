package dialmetrics

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestNodeDNSAndTCPAreSeparated(t *testing.T) {
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2; i++ {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	for _, host := range []string{"127.0.0.1", "localhost"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		c, ph, e := DialOnce(ctx, &net.Dialer{}, "tcp", net.JoinHostPort(host, port))
		cancel()
		if e != nil {
			t.Fatal(e)
		}
		c.Close()
		if ph.TCP <= 0 || ph.DNSRetries != 0 || (host == "127.0.0.1" && ph.DNS != 0) || (host == "localhost" && ph.DNS <= 0) {
			t.Fatal(host, ph)
		}
	}
	<-done
}
