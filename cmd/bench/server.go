package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// serveTarget is a test-only bounded endpoint, not a general proxy.
func serveTarget(address string, echo bool, timeout time.Duration) error {
	l, e := net.Listen("tcp", address)
	if e != nil {
		return e
	}
	defer l.Close()
	slots := make(chan struct{}, 32)
	for {
		c, e := l.Accept()
		if e != nil {
			return e
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { <-slots }()
				defer c.Close()
				if e := c.SetDeadline(time.Now().Add(timeout)); e != nil {
					return
				}
				_ = handleTarget(c, echo)
			}()
		default:
			c.Close()
		}
	}
}
func handleTarget(c net.Conn, echo bool) error {
	if echo {
		_, e := io.Copy(struct{ io.Writer }{c}, struct{ io.Reader }{c})
		return e
	}
	header := make([]byte, 13)
	if _, e := io.ReadFull(c, header); e != nil {
		return e
	}
	if !bytes.Equal(header[:4], []byte("MGB1")) {
		return fmt.Errorf("invalid benchmark protocol")
	}
	size := binary.BigEndian.Uint64(header[5:])
	if size == 0 || size > uint64(maxPayload) {
		return fmt.Errorf("invalid payload size")
	}
	switch header[4] {
	case 1:
		h := sha256.New()
		n, e := io.Copy(h, io.LimitReader(c, int64(size)+1))
		if e != nil {
			return e
		}
		if n != int64(size) {
			return fmt.Errorf("upload size mismatch")
		}
		return writeAll(c, h.Sum(nil))
	case 2:
		if e := expectEOF(c); e != nil {
			return e
		}
		_, e := sendPayload(c, int64(size))
		return e
	default:
		return fmt.Errorf("invalid transfer mode")
	}
}
