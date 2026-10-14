// bench measures an echo target through SOCKS5 without buffering full payloads.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

func main() {
	listen := flag.String("echo", "", "run a TCP echo target at this address")
	socks := flag.String("socks", "127.0.0.1:1080", "SOCKS5 address")
	target := flag.String("target", "127.0.0.1:18081", "echo target as seen by tunnel server")
	mib := flag.Int64("mib", 32, "payload MiB per stream (each byte uploaded and echoed)")
	streams := flag.Int("streams", 1, "parallel streams")
	flag.Parse()
	if *listen != "" {
		l, e := net.Listen("tcp", *listen)
		if e != nil {
			panic(e)
		}
		defer l.Close()
		for {
			c, e := l.Accept()
			if e != nil {
				panic(e)
			}
			go func() { defer c.Close(); io.Copy(struct{ io.Writer }{c}, struct{ io.Reader }{c}) }()
		}
	}
	if *mib < 1 || *mib > 4096 || *streams < 1 || *streams > 128 {
		fmt.Fprintln(os.Stderr, "mib: 1..4096; streams: 1..128")
		os.Exit(2)
	}
	start := time.Now()
	var wg sync.WaitGroup
	errs := make(chan error, *streams)
	for i := 0; i < *streams; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- transfer(*socks, *target, *mib<<20) }()
	}
	wg.Wait()
	close(errs)
	failures := 0
	for e := range errs {
		if e != nil {
			failures++
			fmt.Fprintln(os.Stderr, e)
		}
	}
	sec := time.Since(start).Seconds()
	json.NewEncoder(os.Stdout).Encode(map[string]any{"streams": *streams, "mib_per_stream": *mib, "seconds": sec, "payload_mib_per_second": float64(*mib*int64(*streams)) / sec, "bidirectional_mib_per_second": 2 * float64(*mib*int64(*streams)) / sec, "failures": failures})
	if failures > 0 {
		os.Exit(1)
	}
}
func transfer(socks, target string, size int64) error {
	c, e := net.DialTimeout("tcp", socks, 10*time.Second)
	if e != nil {
		return e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Minute))
	if _, e = c.Write([]byte{5, 1, 0}); e != nil {
		return e
	}
	b := make([]byte, 2)
	if _, e = io.ReadFull(c, b); e != nil {
		return e
	}
	if !bytes.Equal(b, []byte{5, 0}) {
		return fmt.Errorf("SOCKS method: %v", b)
	}
	host, port, e := net.SplitHostPort(target)
	if e != nil {
		return e
	}
	if len(host) > 255 {
		return fmt.Errorf("host too long")
	}
	p, e := net.LookupPort("tcp", port)
	if e != nil {
		return e
	}
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, []byte(host)...)
	req = binary.BigEndian.AppendUint16(req, uint16(p))
	if _, e = c.Write(req); e != nil {
		return e
	}
	head := make([]byte, 4)
	if _, e = io.ReadFull(c, head); e != nil {
		return e
	}
	if head[0] != 5 || head[1] != 0 || head[2] != 0 {
		return fmt.Errorf("SOCKS reply: %v", head)
	}
	n := 0
	switch head[3] {
	case 1:
		n = 6
	case 4:
		n = 18
	case 3:
		if _, e = io.ReadFull(c, b[:1]); e != nil {
			return e
		}
		n = int(b[0]) + 2
	default:
		return fmt.Errorf("bad address type")
	}
	if _, e = io.CopyN(io.Discard, c, int64(n)); e != nil {
		return e
	}
	sent := make(chan error, 1)
	expected := make(chan []byte, 1)
	go func() {
		h := sha256.New()
		chunk := make([]byte, 64<<10)
		for i := range chunk {
			chunk[i] = byte(i*31 + 7)
		}
		var err error
		for left := size; left > 0; {
			n := min(int64(len(chunk)), left)
			_, err = io.Copy(c, io.TeeReader(bytes.NewReader(chunk[:n]), h))
			if err != nil {
				break
			}
			left -= n
		}
		expected <- h.Sum(nil)
		if err == nil {
			err = c.(*net.TCPConn).CloseWrite()
		}
		sent <- err
	}()
	h := sha256.New()
	received, err := io.Copy(h, c)
	if err != nil {
		c.Close()
	}
	sendErr := <-sent
	want := <-expected
	if err != nil {
		return err
	}
	if sendErr != nil {
		return sendErr
	}
	if received != size || !bytes.Equal(h.Sum(nil), want) {
		return fmt.Errorf("payload mismatch: got %d want %d", received, size)
	}
	return nil
}
