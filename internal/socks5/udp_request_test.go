package socks5

import (
	"bytes"
	"net"
	"testing"
)

func TestUDPAssociateRequestDetails(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire []byte
		host string
		port uint16
	}{
		{"IPv4 wildcard", []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}, "0.0.0.0", 0},
		{"IPv4 explicit", []byte{5, 3, 0, 1, 127, 0, 0, 1, 0x1f, 0x90}, "127.0.0.1", 8080},
		{"domain", append([]byte{5, 3, 0, 3, 9}, []byte("localhost\x00\x00")...), "localhost", 0},
		{"IPv6", append(append([]byte{5, 3, 0, 4}, net.ParseIP("::1").To16()...), 0, 0), "::1", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := ReadRequestDetails(requestConn{reader: bytes.NewReader(tc.wire)})
			if err != nil || r.Command != CommandUDPAssociate || r.Address != tc.host || r.Port != tc.port {
				t.Fatalf("%+v %v", r, err)
			}
		})
	}
}
