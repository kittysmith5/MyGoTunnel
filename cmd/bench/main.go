// bench verifies streaming echo, upload and download through SOCKS5.
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

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type options struct {
	Mode    string
	Auth    *credentials
	Timeout time.Duration
}

const maxPayload = int64(4096) << 20

func validAuth(a *credentials) bool {
	return a == nil || (len(a.Username) > 0 && len(a.Username) <= 255 && len(a.Password) > 0 && len(a.Password) <= 255)
}
func main() {
	echo := flag.String("echo", "", "serve legacy echo target")
	serve := flag.String("serve", "", "serve bounded upload/download target (keep on loopback)")
	socks := flag.String("socks", "127.0.0.1:1080", "SOCKS5 endpoint")
	target := flag.String("target", "127.0.0.1:18081", "target as seen by tunnel server")
	mode := flag.String("mode", "echo", "echo, upload, download")
	authFile := flag.String("auth-file", "", "private JSON file containing username and password")
	timeout := flag.Duration("timeout", 5*time.Minute, "total per-stream deadline, including SOCKS setup")
	mib := flag.Int64("mib", 32, "payload MiB per stream")
	streams := flag.Int("streams", 1, "parallel streams (1..128)")
	flag.Parse()
	fail := func(e error) { fmt.Fprintln(os.Stderr, e); os.Exit(2) }
	if *timeout <= 0 || *mib < 1 || *mib > 4096 || *streams < 1 || *streams > 128 || (*mode != "echo" && *mode != "upload" && *mode != "download") || (*echo != "" && *serve != "") {
		fail(fmt.Errorf("invalid mode, limits or timeout"))
	}
	if *echo != "" || *serve != "" {
		addr := *serve
		if *echo != "" {
			addr = *echo
		}
		if e := serveTarget(addr, *echo != "", *timeout); e != nil {
			fail(e)
		}
		return
	}
	o := options{Mode: *mode, Timeout: *timeout}
	if *authFile != "" {
		f, e := os.Open(*authFile)
		if e != nil {
			fail(fmt.Errorf("cannot open auth file"))
		}
		data, e := io.ReadAll(io.LimitReader(f, 4097))
		f.Close()
		o.Auth = &credentials{}
		if e != nil || len(data) > 4096 || json.Unmarshal(data, o.Auth) != nil || !validAuth(o.Auth) {
			fail(fmt.Errorf("invalid auth file: username and password must be 1..255 bytes"))
		}
	}
	start := time.Now()
	var wg sync.WaitGroup
	errs := make(chan error, *streams)
	for i := 0; i < *streams; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- transferWithOptions(*socks, *target, *mib<<20, o) }()
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
	rate := float64(*mib*int64(*streams-failures)) / sec
	wire := rate
	if *mode == "echo" {
		wire *= 2
	}
	if e := json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": *mode, "streams": *streams, "mib_per_stream": *mib, "seconds": sec, "payload_mib_per_second": rate, "bidirectional_mib_per_second": wire, "payload_mbps": rate * 8.388608, "failures": failures}); e != nil {
		fail(e)
	}
	if failures > 0 {
		os.Exit(1)
	}
}
func transfer(socks, target string, size int64) error {
	return transferWithOptions(socks, target, size, options{Mode: "echo", Timeout: 5 * time.Minute})
}
func transferWithOptions(socks, target string, size int64, o options) error {
	if !validAuth(o.Auth) || size <= 0 || size > maxPayload || o.Timeout <= 0 || (o.Mode != "echo" && o.Mode != "upload" && o.Mode != "download") {
		return fmt.Errorf("invalid transfer options")
	}
	start := time.Now()
	c, e := net.DialTimeout("tcp", socks, min(10*time.Second, o.Timeout))
	if e != nil {
		return e
	}
	defer c.Close()
	if e = c.SetDeadline(start.Add(o.Timeout)); e != nil {
		return e
	}
	if e = negotiate(c, o.Auth); e != nil {
		return e
	}
	host, port, e := net.SplitHostPort(target)
	if e != nil {
		return e
	}
	if len(host) == 0 || len(host) > 255 {
		return fmt.Errorf("invalid host")
	}
	p, e := net.LookupPort("tcp", port)
	if e != nil {
		return e
	}
	if p < 1 {
		return fmt.Errorf("invalid port")
	}
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(p))
	if e = writeAll(c, req); e != nil {
		return e
	}
	head := make([]byte, 4)
	if _, e = io.ReadFull(c, head); e != nil {
		return e
	}
	if head[0] != 5 || head[1] != 0 || head[2] != 0 {
		return fmt.Errorf("SOCKS CONNECT rejected")
	}
	n := 0
	switch head[3] {
	case 1:
		n = 6
	case 4:
		n = 18
	case 3:
		b := make([]byte, 1)
		if _, e = io.ReadFull(c, b); e != nil {
			return e
		}
		n = int(b[0]) + 2
	default:
		return fmt.Errorf("invalid SOCKS address type")
	}
	if _, e = io.CopyN(io.Discard, c, int64(n)); e != nil {
		return e
	}
	if o.Mode != "echo" {
		header := append([]byte("MGB1"), byte(1))
		if o.Mode == "download" {
			header[4] = 2
		}
		header = binary.BigEndian.AppendUint64(header, uint64(size))
		if e = writeAll(c, header); e != nil {
			return e
		}
	}
	if o.Mode == "download" {
		if e = c.(*net.TCPConn).CloseWrite(); e != nil {
			return e
		}
		return receivePayload(c, size)
	}
	if o.Mode == "upload" {
		digest, e := sendPayload(c, size)
		if e != nil {
			return e
		}
		if e = c.(*net.TCPConn).CloseWrite(); e != nil {
			return e
		}
		got := make([]byte, sha256.Size)
		if _, e = io.ReadFull(c, got); e != nil {
			return e
		}
		if !bytes.Equal(got, digest) {
			return fmt.Errorf("upload checksum mismatch")
		}
		return expectEOF(c)
	}
	done := make(chan error, 1)
	go func() {
		_, e := sendPayload(c, size)
		if e == nil {
			e = c.(*net.TCPConn).CloseWrite()
		}
		if e != nil {
			c.Close()
		}
		done <- e
	}()
	e = receivePayload(c, size)
	if e != nil {
		c.Close()
	}
	sendErr := <-done
	if e != nil {
		return e
	}
	return sendErr
}
func negotiate(c net.Conn, a *credentials) error {
	method := byte(0)
	if a != nil {
		method = 2
	}
	if e := writeAll(c, []byte{5, 1, method}); e != nil {
		return e
	}
	b := make([]byte, 2)
	if _, e := io.ReadFull(c, b); e != nil {
		return e
	}
	if b[0] != 5 || b[1] != method {
		return fmt.Errorf("SOCKS authentication method rejected")
	}
	if a == nil {
		return nil
	}
	req := append([]byte{1, byte(len(a.Username))}, a.Username...)
	req = append(req, byte(len(a.Password)))
	req = append(req, a.Password...)
	if e := writeAll(c, req); e != nil {
		return e
	}
	if _, e := io.ReadFull(c, b); e != nil {
		return e
	}
	if b[0] != 1 || b[1] != 0 {
		return fmt.Errorf("SOCKS authentication rejected")
	}
	return nil
}
func writeAll(w io.Writer, b []byte) error {
	n, e := w.Write(b)
	if e == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return e
}
func sendPayload(w io.Writer, size int64) ([]byte, error) {
	h := sha256.New()
	chunk := make([]byte, 64<<10)
	for i := range chunk {
		chunk[i] = byte(i*31 + 7)
	}
	for left := size; left > 0; {
		n := min(int64(len(chunk)), left)
		if e := writeAll(io.MultiWriter(w, h), chunk[:n]); e != nil {
			return nil, e
		}
		left -= n
	}
	return h.Sum(nil), nil
}
func receivePayload(r io.Reader, size int64) error {
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(r, size+1))
	if e != nil {
		return e
	}
	if n != size {
		return fmt.Errorf("payload size mismatch: got %d want %d", n, size)
	}
	expected, e := sendPayload(io.Discard, size)
	if e != nil {
		return e
	}
	if !bytes.Equal(h.Sum(nil), expected) {
		return fmt.Errorf("payload checksum mismatch")
	}
	return nil
}
func expectEOF(r io.Reader) error {
	b := make([]byte, 1)
	n, e := r.Read(b)
	if n == 0 && e == io.EOF {
		return nil
	}
	if e != nil {
		return e
	}
	return fmt.Errorf("unexpected trailing payload")
}
