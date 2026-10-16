package socks5

import (
	"io"
	"net"
	"testing"
	"time"
)

type stageDelayConn struct {
	net.Conn
	reads, delayAt int
}

func (c *stageDelayConn) Read(p []byte) (int, error) {
	c.reads++
	if c.reads == c.delayAt {
		time.Sleep(10 * time.Millisecond)
	}
	return c.Conn.Read(p)
}

func TestHandshakeTimingsSeparatePeerWaits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		read  int
		stage func(HandshakeTimings) time.Duration
	}{
		{"first_byte", 1, func(v HandshakeTimings) time.Duration { return v.FirstByte }},
		{"method", 2, func(v HandshakeTimings) time.Duration { return v.Method }},
		{"auth", 4, func(v HandshakeTimings) time.Duration { return v.Auth }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			a.SetDeadline(time.Now().Add(time.Second))
			b.SetDeadline(time.Now().Add(time.Second))
			result := make(chan HandshakeTimings, 1)
			errs := make(chan error, 1)
			go func() {
				v, e := HandshakeWithAuthTimings(&stageDelayConn{Conn: a, delayAt: tc.read}, &Credentials{"u", "p"})
				result <- v
				errs <- e
			}()
			if _, err := b.Write([]byte{5, 1, 2}); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, 2)
			if _, err := io.ReadFull(b, reply); err != nil || reply[1] != 2 {
				t.Fatalf("method: %v %v", reply, err)
			}
			if _, err := b.Write([]byte{1, 1, 'u', 1, 'p'}); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(b, reply); err != nil || reply[1] != 0 {
				t.Fatalf("auth: %v %v", reply, err)
			}
			v := <-result
			if err := <-errs; err != nil {
				t.Fatal(err)
			}
			if tc.stage(v) < 10*time.Millisecond {
				t.Fatalf("wait attributed to wrong stage: %+v", v)
			}
		})
	}
}

func TestHandshakeTimingsOnFirstByteFailure(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	b.Close()
	got, err := HandshakeWithAuthTimings(a, nil)
	if err == nil || got.Method != 0 || got.Auth != 0 {
		t.Fatalf("timings on EOF: %+v, %v", got, err)
	}
}
