package main

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestTransferStreamingHalfClose(t *testing.T) {
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
		c.SetDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 3)
		if _, e = io.ReadFull(c, b); e != nil {
			done <- e
			return
		}
		c.Write([]byte{5, 0})
		head := make([]byte, 5)
		if _, e = io.ReadFull(c, head); e != nil {
			done <- e
			return
		}
		if _, e = io.CopyN(io.Discard, c, int64(head[4])+2); e != nil {
			done <- e
			return
		}
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		_, e = io.Copy(struct{ io.Writer }{c}, struct{ io.Reader }{c})
		done <- e
	}()
	if e := transfer(l.Addr().String(), "echo.test:12345", 2<<20); e != nil {
		t.Fatal(e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
