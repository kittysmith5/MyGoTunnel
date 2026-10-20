package main

import (
	"bytes"
	"net"
	"testing"
	"time"

	"mygotunnel/internal/datagram"
	"mygotunnel/internal/socks5"
)

func TestUDPResidentAdmissionRejectsNewAssociationsAndKeepsExistingWorking(t *testing.T) {
	resources := datagram.NewResources(4, 262144)
	defer resources.Close()
	request := socks5.Request{Command: socks5.CommandUDPAssociate, Address: "0.0.0.0"}
	first := newUDPAssociationTest(t, request, resources)
	second := newUDPAssociationTest(t, request, resources)
	sender := testUDPSocket(t, "127.0.0.1")
	packet := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "example.test", Port: 53}, []byte("existing"))
	checkFirst := func() {
		t.Helper()
		if _, err := sender.WriteToUDP(packet, first.relay); err != nil {
			t.Fatal(err)
		}
		if err := sender.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 100)
		if n, _, err := sender.ReadFromUDP(buffer); err != nil || !bytes.Equal(buffer[:n], packet) {
			t.Fatal("idle associations starved existing UDP", err)
		}
	}
	checkFirst()
	for i := 0; i < 2; i++ {
		newUDPAssociationTestReply(t, request, 0x01, net.DefaultResolver.LookupIPAddr, resources)
		checkFirst()
	}
	if s := resources.Stats(); s.Sockets != 2 || s.ResidentBytes != 131072 || s.ResidentRejected != 2 || s.BufferBytes > s.MemoryLimit {
		t.Fatal(s)
	}
	first.control.Close()
	second.control.Close()
	<-first.done
	<-second.done
	if s := resources.Stats(); s.Sockets != 0 || s.ResidentBytes != 0 || s.BufferBytes != s.CachedBytes {
		t.Fatal("association shutdown leaked resources", s)
	}
}
