package main

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestAuthenticatedModes(t *testing.T) {
	for _, mode := range []string{"echo", "upload", "download"} {
		t.Run(mode, func(t *testing.T) {
			l, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			done := make(chan error, 1)
			go func() {
				c, e := l.Accept()
				if e != nil {
					done <- e
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				b := make([]byte, 3)
				if _, e = io.ReadFull(c, b); e != nil {
					done <- e
					return
				}
				if b[2] != 2 {
					t.Error("auth not offered")
				}
				writeAll(c, []byte{5, 2})
				a := make([]byte, 2)
				io.ReadFull(c, a)
				u := make([]byte, int(a[1]))
				io.ReadFull(c, u)
				io.ReadFull(c, a[:1])
				p := make([]byte, int(a[0]))
				io.ReadFull(c, p)
				if string(u) != "test-user" || string(p) != "test-password" {
					t.Error("incorrect credentials")
				}
				writeAll(c, []byte{1, 0})
				head := make([]byte, 5)
				io.ReadFull(c, head)
				io.CopyN(io.Discard, c, int64(head[4])+2)
				writeAll(c, []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				done <- handleTarget(c, mode == "echo")
			}()
			if e := transferWithOptions(l.Addr().String(), "echo.test:18081", 1<<20, options{Mode: mode, Auth: &credentials{"test-user", "test-password"}, Timeout: 3 * time.Second}); e != nil {
				t.Fatal(e)
			}
			if e := <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestBenchmarkRejectsAuthDowngrade(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(time.Second))
	b.SetDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() { done <- negotiate(a, &credentials{"user", "password"}) }()
	io.ReadFull(b, make([]byte, 3))
	writeAll(b, []byte{5, 0})
	if <-done == nil {
		t.Fatal("auth downgrade accepted")
	}
}
func TestBenchmarkRejectsCorruptPayload(t *testing.T) {
	if e := receivePayload(&zeroReader{left: 1024}, 1024); e == nil {
		t.Fatal("corruption accepted")
	}
}

type zeroReader struct{ left int }

func (r *zeroReader) Read(p []byte) (int, error) {
	if r.left == 0 {
		return 0, io.EOF
	}
	n := min(len(p), r.left)
	clear(p[:n])
	r.left -= n
	return n, nil
}
