package socks5

import (
	"bytes"
	"net"
	"testing"
)

type requestConn struct {
	net.Conn
	reader *bytes.Reader
}

func (c requestConn) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return c.reader.Read(p)
}

func TestReadRequest(t *testing.T) {
	domain := func(host string, port []byte) []byte {
		request := append([]byte{5, 1, 0, 3, byte(len(host))}, []byte(host)...)
		return append(request, port...)
	}
	tests := []struct {
		name  string
		input []byte
		want  string
		rep   byte
	}{
		{"IPv4", []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80}, "127.0.0.1:80", 0},
		{"domain", domain("example.com", []byte{1, 187}), "example.com:443", 0},
		{"IPv6", append(append([]byte{5, 1, 0, 4}, net.ParseIP("::1").To16()...), 0, 80), "[::1]:80", 0},
		{"invalid version", []byte{4, 1, 0, 1}, "", 1},
		{"invalid reserved", []byte{5, 1, 1, 1}, "", 1},
		{"unsupported command", []byte{5, 3, 0, 1}, "", 7},
		{"unsupported address", []byte{5, 1, 0, 9}, "", 8},
		{"empty domain", domain("", []byte{0, 80}), "", 8},
		{"newline", domain("a\nCONNECT b", []byte{0, 80}), "", 8},
		{"NUL", domain("a\x00b", []byte{0, 80}), "", 8},
		{"space", domain("a b", []byte{0, 80}), "", 8},
		{"colon", domain("a:b", []byte{0, 80}), "", 8},
		{"zero port", domain("example.com", []byte{0, 0}), "", 1},
		{"short header", []byte{5, 1}, "", 1},
		{"short domain", []byte{5, 1, 0, 3, 10, 'a'}, "", 1},
		{"short port", domain("example.com", []byte{0}), "", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadRequest(requestConn{reader: bytes.NewReader(tt.input)})
			if got != tt.want || (err != nil) != (tt.rep != 0) {
				t.Fatalf("got %q, %v; want %q, rep %d", got, err, tt.want, tt.rep)
			}
			if err != nil && ReplyCode(err) != tt.rep {
				t.Fatalf("rep = %d, want %d", ReplyCode(err), tt.rep)
			}
		})
	}
}
