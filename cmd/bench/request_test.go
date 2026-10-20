package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"mygotunnel/internal/socks5"
)

func TestBenchmarkAddressTypesRelayThroughSOCKSParser(t *testing.T) {
	for _, tc := range []struct {
		target, host string
		atyp         byte
	}{
		{"192.0.2.1:443", "192.0.2.1", 1},
		{"[2001:db8::1]:443", "2001:db8::1", 4},
		{"[::ffff:192.0.2.1]:443", "192.0.2.1", 1},
		{"echo.test:443", "echo.test", 3},
	} {
		t.Run(tc.target, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			done := make(chan error, 1)
			go func() {
				c, err := l.Accept()
				if err != nil {
					done <- err
					return
				}
				defer c.Close()
				if err = c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
					done <- err
					return
				}
				if err = socks5.Handshake(c); err != nil {
					done <- err
					return
				}
				request, err := socks5.ReadRequestDetails(c)
				if err != nil {
					done <- err
					return
				}
				if request.Command != 1 || request.Address != tc.host || request.Port != 443 {
					done <- fmt.Errorf("incorrect request: %+v", request)
					return
				}
				if err = socks5.Reply(c, 0); err != nil {
					done <- err
					return
				}
				_, err = io.Copy(struct{ io.Writer }{c}, struct{ io.Reader }{c})
				done <- err
			}()
			packet, err := buildConnectRequest(tc.target)
			if err != nil || len(packet) < 4 || packet[3] != tc.atyp {
				t.Fatal("wrong address type", packet, err)
			}
			if err = transferWithOptions(l.Addr().String(), tc.target, 65536, options{Mode: "echo", Timeout: 3 * time.Second}); err != nil {
				t.Fatal(err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBenchmarkRejectsUnencodableTargets(t *testing.T) {
	for _, target := range []string{"[fe80::1%eth0]:443", "echo.test:0", "echo.test:65536", ":443", strings.Repeat("x", 256) + ":443", "bad host:443", "[invalid:ipv6]:443"} {
		if packet, err := buildConnectRequest(target); err == nil {
			t.Fatalf("accepted %q: %v", target, packet)
		}
	}
	packet, err := buildConnectRequest("echo.test:443")
	if err != nil || !bytes.Equal(packet[len(packet)-2:], []byte{1, 187}) {
		t.Fatal("target port changed", packet, err)
	}
}
