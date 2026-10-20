package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/socks5"
)

func TestUDPSourceFilterKeepsIPv6InterfaceScopeAfterBinding(t *testing.T) {
	f := newUDPSourceFilter([]net.IP{net.ParseIP("fe80::1")}, 0)
	first := netip.MustParseAddrPort("[fe80::1%test0]:1234")
	if why := f.rejection(first); why != "" {
		t.Fatal(why)
	}
	f.bound = first
	if why := f.rejection(first); why != "" {
		t.Fatal(why)
	}
	if why := f.rejection(netip.MustParseAddrPort("[fe80::1%test1]:1234")); why != "binding" {
		t.Fatal("interface scope was not pinned", why)
	}
}

func TestUDPNATModeLearnsMappedEndpointAndReportsDrops(t *testing.T) {
	session := newUDPAssociationTestConfig(t, socks5.Request{Command: 3, Address: "private-source.invalid", Port: 1}, 0,
		func(context.Context, string) ([]net.IPAddr, error) {
			t.Error("NAT mode resolved an advisory source domain")
			return nil, nil
		},
		&config.ClientConfig{UDPSourcePolicy: "nat"})
	foreign, malformed, sender := testUDPSocket(t, "127.0.0.2"), testUDPSocket(t, "127.0.0.1"), testUDPSocket(t, "127.0.0.1")
	packet := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "target.test", Port: 53}, []byte("nat"))
	assertDrop := func(conn *net.UDPConn, p []byte) {
		t.Helper()
		if _, err := conn.WriteToUDP(p, session.relay); err != nil {
			t.Fatal(err)
		}
		conn.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
		if _, _, err := conn.ReadFromUDP(make([]byte, 100)); err == nil {
			t.Fatal("unauthorized/malformed datagram was forwarded")
		}
	}
	assertDrop(foreign, packet)
	assertDrop(malformed, []byte{0, 0, 1, 1})
	if _, err := sender.WriteToUDP(packet, session.relay); err != nil {
		t.Fatal(err)
	}
	sender.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 100)
	n, _, err := sender.ReadFromUDP(buffer)
	if err != nil || !bytes.Equal(buffer[:n], packet) {
		t.Fatalf("mapped port was not learned: %v", err)
	}
	assertDrop(malformed, packet) // a second valid port cannot take over
	session.control.Close()
	select {
	case <-session.done:
	case <-time.After(time.Second):
		t.Fatal("NAT session did not stop")
	}
	for _, want := range []string{"received_datagrams=4", "source_ip_drops=1", "invalid_datagrams=1", "source_binding_drops=1", "first_datagram_seen=true", "upload_datagrams=1", "download_datagrams=1"} {
		if !strings.Contains(session.logs.String(), want) {
			t.Fatalf("missing %s: %s", want, session.logs.String())
		}
	}
}

func TestUDPRelayPortRangeHandlesOccupiedAndAvailablePort(t *testing.T) {
	reserved := testUDPSocket(t, "127.0.0.1")
	port := reserved.LocalAddr().(*net.UDPAddr).Port
	cfg := &config.ClientConfig{UDPRelayPortMin: port, UDPRelayPortMax: port}
	if conn, err := listenUDPRelay(net.IPv4(127, 0, 0, 1), cfg); err == nil {
		conn.Close()
		t.Fatal("occupied range accepted")
	} else if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatal(err)
	}
	reserved.Close()
	conn, err := listenUDPRelay(net.IPv4(127, 0, 0, 1), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.LocalAddr().(*net.UDPAddr).Port != port {
		t.Fatal(conn.LocalAddr())
	}
}
