package main

import (
	"bytes"
	"net"
	"testing"
	"time"

	"mygotunnel/internal/datagram"
	"mygotunnel/internal/tunnel"
)

func TestUDPResidentTargetLimitPreservesHealthyTargets(t *testing.T) {
	resources := datagram.NewResources(20, 262144)
	defer resources.Close()
	conn, reader := startUDPRecoverySession(t, (&net.Dialer{}).DialContext, resources)
	var first []byte
	check := func(packet []byte) {
		t.Helper()
		if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := tunnel.WriteDatagram(conn, packet); err != nil {
			t.Fatal(err)
		}
		if got, err := tunnel.ReadDatagram(reader); err != nil || !bytes.Equal(got, packet) {
			t.Fatal("new target starved healthy target", err)
		}
	}
	for i := 0; i < 4; i++ {
		_, packet := udpIsolationEcho(t)
		if i == 0 {
			first = packet
		}
		if i < 2 {
			check(packet)
			continue
		}
		if err := conn.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if err := tunnel.WriteDatagram(conn, packet); err != nil {
			t.Fatal(err)
		}
		if _, err := tunnel.ReadDatagram(reader); err == nil {
			t.Fatal("new target consumed existing targets' transient reserve")
		}
		check(first)
	}
	waitUDPRecoverySockets(t, resources, 2)
	if s := resources.Stats(); s.ResidentBytes != 131072 || s.ResidentRejected != 2 || s.BufferBytes > s.MemoryLimit {
		t.Fatal(s)
	}
	conn.Close()
	waitUDPRecoverySockets(t, resources, 0)
	if s := resources.Stats(); s.ResidentBytes != 0 {
		t.Fatal("closed targets kept resident reservations", s)
	}
}
