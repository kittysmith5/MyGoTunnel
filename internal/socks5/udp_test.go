package socks5

import (
	"bytes"
	"net"
	"testing"
)

func TestUDPDatagramRoundTrip(t *testing.T) {
	want := []byte("dns payload")
	packet := BuildUDPDatagram(UDPDatagram{Host: "example.com", Port: 53}, want)
	destination, payload, err := ParseUDPDatagram(packet)
	if err != nil {
		t.Fatalf("ParseUDPDatagram() error = %v", err)
	}
	if destination != (UDPDatagram{Host: "example.com", Port: 53}) {
		t.Fatalf("destination = %#v", destination)
	}
	if !bytes.Equal(payload, want) {
		t.Fatalf("payload = %q, want %q", payload, want)
	}
}

func TestParseUDPDatagramRejectsFragments(t *testing.T) {
	_, _, err := ParseUDPDatagram([]byte{0, 0, 1, 1})
	if err == nil {
		t.Fatal("ParseUDPDatagram() unexpectedly accepted a fragmented packet")
	}
}

func TestUDPDatagramRejectsInvalidDestinationBeforePayload(t *testing.T) {
	for _, host := range []string{"", "a\x00b", "a\nb", "a\x7fb", "a\u0085b", "a b", "a:b", "a/b", "a\\b", "[a]"} {
		t.Run(host, func(t *testing.T) {
			packet := BuildUDPDatagram(UDPDatagram{Host: host, Port: 53}, nil)
			if _, _, err := ParseUDPDatagram(packet); err == nil || ReplyCode(err) != 0x08 {
				t.Fatalf("invalid UDP domain accepted: %v", err)
			}
			request := append([]byte{5, CommandConnect, 0, 3, byte(len(host))}, host...)
			request = append(request, 0, 53)
			if _, err := ReadRequestDetails(requestConn{reader: bytes.NewReader(request)}); err == nil || ReplyCode(err) != 0x08 {
				t.Fatalf("TCP and UDP domain validation differ: %v", err)
			}
		})
	}
	for _, host := range []string{"127.0.0.1", "::1", "example.test"} {
		t.Run("zero port "+host, func(t *testing.T) {
			if _, _, err := ParseUDPDatagram(BuildUDPDatagram(UDPDatagram{Host: host}, nil)); err == nil || ReplyCode(err) != 0x01 {
				t.Fatalf("zero destination port accepted: %v", err)
			}
		})
	}
}

func TestUDPDatagramAllowsZeroPayloadForAllAddressTypes(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "example.test"} {
		t.Run(host, func(t *testing.T) {
			want := UDPDatagram{Host: host, Port: 53}
			got, payload, err := ParseUDPDatagram(BuildUDPDatagram(want, nil))
			if err != nil || got != want || len(payload) != 0 {
				t.Fatalf("zero-length payload: destination=%+v payload=%q error=%v", got, payload, err)
			}
		})
	}
}

func TestUDPAssociatePortZeroStillAllowsWildcard(t *testing.T) {
	for _, ip := range []net.IP{net.IPv4zero.To4(), net.IPv6unspecified} {
		atyp := byte(1)
		if len(ip) == net.IPv6len {
			atyp = 4
		}
		request := append([]byte{5, CommandUDPAssociate, 0, atyp}, ip...)
		request = append(request, 0, 0)
		if got, err := ReadRequestDetails(requestConn{reader: bytes.NewReader(request)}); err != nil || got.Port != 0 {
			t.Fatalf("ASSOCIATE wildcard port rejected: %+v %v", got, err)
		}
	}
}
