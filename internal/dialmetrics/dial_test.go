package dialmetrics

import (
	"context"
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
