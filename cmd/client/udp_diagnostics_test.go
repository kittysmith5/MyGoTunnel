package main

import (
	"bytes"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"mygotunnel/internal/socks5"
)

func TestUDPSourceDiagnosticsPreserveFilterAndForwarding(t *testing.T) {
	for _, tc := range []struct {
		name, allowed, rejected string
		natCandidate            bool
	}{
		{"declaration differs from TCP peer", "127.0.0.2", "127.0.0.1", true},
		{"rejected IP differs from TCP peer", "127.0.0.1", "127.0.0.2", false},
	} {
		t.Run(tc.name, func(t *testing.T) { testUDPSourceDiagnostics(t, tc.allowed, tc.rejected, tc.natCandidate) })
	}
}

func testUDPSourceDiagnostics(t *testing.T, allowedIP, rejectedIP string, natCandidate bool) {
	t.Helper()
	s := newUDPAssociationTest(t, socks5.Request{Command: 3, Address: allowedIP})
	wrong := testUDPSocket(t, rejectedIP)
	allowed := testUDPSocket(t, allowedIP)
	packet := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "192.0.2.1", Port: 53}, []byte("diagnostic-payload"))
	for range 5 {
		if _, err := wrong.WriteToUDP(packet, s.relay); err != nil {
			t.Fatal(err)
		}
	}
	// A malformed packet from the right IP must not bind its endpoint or count
	// as an accepted first packet. A later valid packet must still pass.
	if _, err := allowed.WriteToUDP([]byte{0}, s.relay); err != nil {
		t.Fatal(err)
	}
	if _, err := allowed.WriteToUDP(packet, s.relay); err != nil {
		t.Fatal(err)
	}
	_ = allowed.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, len(packet)+1)
	n, _, err := allowed.ReadFromUDP(buf)
	if err != nil || !bytes.Equal(buf[:n], packet) {
		t.Fatalf("valid datagram did not survive diagnostic path: n=%d err=%v", n, err)
	}
	_ = s.control.Close()
	select {
	case <-s.done:
	case <-time.After(time.Second):
		t.Fatal("association failed to stop")
	}
	log := s.logs.String()
	for _, want := range []string{"udp_source_declared_addr=" + net.JoinHostPort(allowedIP, "0"), "udp_source_allowed_ips=" + allowedIP, "udp_source_allowed_count=1",
		"udp_source_first_rejected_addr=" + wrong.LocalAddr().String(), "udp_source_first_rejected_reason=ip", "udp_source_rejected_matches_tcp_peer=" + strconv.FormatBool(natCandidate), "udp_source_nat_candidate=" + strconv.FormatBool(natCandidate),
		"source_ip_drops=5", "invalid_datagrams=1", "upload_datagrams=1", "download_datagrams=1", "first_datagram_seen=true", "first_accepted_datagram_seen=true"} {
		if !strings.Contains(log, want) {
			t.Errorf("missing %q in %s", want, log)
		}
	}
	if strings.Contains(log, "diagnostic-payload") || strings.Count(log, "udp_source_first_rejected_addr=") != 1 {
		t.Fatal("source diagnostic leaked payload or emitted per-packet samples", log)
	}
}

func TestUDPSourceDiagnosticsBoundPresentation(t *testing.T) {
	var ips []net.IP
	for i := byte(1); i <= 20; i++ {
		ips = append(ips, net.IPv4(192, 0, 2, i))
	}
	if got := udpSourceIPSummary(ips); strings.Count(got, ",") != 7 || strings.Contains(got, "192.0.2.9") || !strings.Contains(got, "192.0.2.8") {
		t.Fatal("source summary is not bounded", got)
	}
	s := newUDPAssociationTest(t, socks5.Request{Command: 3, Address: "0.0.0.0"})
	_ = s.control.Close()
	select {
	case <-s.done:
	case <-time.After(time.Second):
		t.Fatal("association failed to stop")
	}
	if !strings.Contains(s.logs.String(), "first_accepted_datagram_seen=false") || !strings.Contains(s.logs.String(), "first_accepted_datagram_duration=0s") {
		t.Fatal("unused association reported a valid first packet", s.logs.String())
	}
}
