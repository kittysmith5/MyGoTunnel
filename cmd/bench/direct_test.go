package main

import (
	"bytes"
	"crypto/subtle"
	"io"
	"net"
	"testing"
	"time"
)

func TestDirectModesAndMeters(t *testing.T) {
	for _, mode := range []string{"echo", "upload", "download"} {
		t.Run(mode, func(t *testing.T) {
			key := bytes.Repeat([]byte{9}, 32)
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
				c.SetDeadline(time.Now().Add(time.Second))
				got := make([]byte, 32)
				if _, e = io.ReadFull(c, got); e != nil {
					done <- e
					return
				}
				if subtle.ConstantTimeCompare(got, key) != 1 {
					t.Error("wrong target key")
				}
				done <- handleTarget(c, mode == "echo")
			}()
			meter := &progress{}
			o := options{Mode: mode, Timeout: time.Second, Direct: true, TargetKey: key, Progress: meter}
			if e := transferWithOptions("unused-invalid-socks", l.Addr().String(), 1<<20, o); e != nil {
				t.Fatal(e)
			}
			if e := <-done; e != nil {
				t.Fatal(e)
			}
			wantTX, wantRX := int64(1<<20), int64(1<<20)
			if mode == "upload" {
				wantRX = 0
			}
			if mode == "download" {
				wantTX = 0
			}
			if meter.tx.Load() != wantTX || meter.rx.Load() != wantRX {
				t.Fatalf("meters %d/%d", meter.tx.Load(), meter.rx.Load())
			}
		})
	}
}

func TestTargetKeyRejection(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	if checkTargetKey(bytes.NewReader(key), key) != nil {
		t.Fatal("valid key rejected")
	}
	if checkTargetKey(bytes.NewReader(bytes.Repeat([]byte{8}, 32)), key) == nil {
		t.Fatal("wrong key accepted")
	}
	if checkTargetKey(bytes.NewReader(key[:16]), key) == nil {
		t.Fatal("truncated key accepted")
	}
}
