package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
)

type udpAssociationTest struct {
	control net.Conn
	remote  net.Conn
	relay   *net.UDPAddr
	done    <-chan struct{}
}

// Exercise the real uTLS connection and TCP peer addresses without using an
// external server. The remote stub echoes framed SOCKS UDP packets unchanged.
func newUDPAssociationTest(t *testing.T, request socks5.Request) udpAssociationTest {
	t.Helper()
	certSource := httptest.NewTLSServer(nil)
	cert := certSource.TLS.Certificates[0]
	certSource.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	remoteConn := make(chan net.Conn, 1)
	remoteDone := make(chan struct{})
	go func() {
		defer close(remoteDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		remoteConn <- conn
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(conn)
		for _, want := range []string{"AUTH test-token", "UDP"} {
			line, err := tunnel.ReadLine(reader)
			if err != nil || line != want {
				return
			}
			if err := tunnel.SendOK(conn); err != nil {
				return
			}
		}
		for {
			packet, err := tunnel.ReadDatagram(reader)
			if err != nil {
				return
			}
			if err := tunnel.WriteDatagram(conn, packet); err != nil {
				_, _ = io.Copy(io.Discard, conn)
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-remoteDone:
		case <-time.After(6 * time.Second):
			t.Error("remote UDP stub did not stop")
		}
	})
	local, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	control, err := net.Dial("tcp4", local.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	clientConn, err := local.Accept()
	if err != nil {
		control.Close()
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer clientConn.Close()
		handleUDPAssociate(clientConn, request, &config.ClientConfig{
			RemoteAddr: listener.Addr().String(), AuthToken: "test-token",
		}, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Now())
	}()
	t.Cleanup(func() {
		_ = control.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("UDP association workers did not stop")
		}
	})
	_ = control.SetReadDeadline(time.Now().Add(3 * time.Second))
	var reply [10]byte
	if _, err := io.ReadFull(control, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 5 || reply[1] != 0 || reply[3] != 1 {
		t.Fatalf("UDP association reply: %v", reply)
	}
	return udpAssociationTest{
		control: control, remote: <-remoteConn, done: done,
		relay: &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(binary.BigEndian.Uint16(reply[8:]))},
	}
}

func testUDPSocket(t *testing.T, ip string) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestUDPAssociationRejectsForeignSourceAndInvalidFirstPacket(t *testing.T) {
	session := newUDPAssociationTest(t, socks5.Request{Command: 3, Address: "0.0.0.0"})
	foreign := testUDPSocket(t, "127.0.0.2")
	malformed := testUDPSocket(t, "127.0.0.1")
	legitimate := testUDPSocket(t, "127.0.0.1")
	packet := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "192.0.2.1", Port: 53}, []byte("echo"))
	oversized := make([]byte, tunnel.MaxDatagramSize+1)
	copy(oversized, packet)
	for _, bad := range []struct {
		conn   *net.UDPConn
		packet []byte
	}{{foreign, packet}, {malformed, []byte{0, 0, 1, 1}}, {malformed, oversized}} {
		if _, err := bad.conn.WriteToUDP(bad.packet, session.relay); err != nil {
			t.Fatal(err)
		}
		_ = bad.conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		if _, _, err := bad.conn.ReadFromUDP(make([]byte, 100)); err == nil {
			t.Fatal("invalid source or malformed packet received a response")
		} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			t.Fatal(err)
		}
	}
	if _, err := legitimate.WriteToUDP(packet, session.relay); err != nil {
		t.Fatal(err)
	}
	_ = legitimate.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 100)
	n, _, err := legitimate.ReadFromUDP(buffer)
	if err != nil || !bytes.Equal(buffer[:n], packet) {
		t.Fatalf("legitimate peer was blocked: %v, %v", buffer[:n], err)
	}
	// Even another valid packet from the same IP cannot move an association
	// away from the source port already chosen by a legitimate packet.
	if _, err := malformed.WriteToUDP(packet, session.relay); err != nil {
		t.Fatal(err)
	}
	_ = malformed.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := malformed.ReadFromUDP(buffer); err == nil {
		t.Fatal("association accepted a different source port after binding")
	}
}

func TestUDPAssociationHonorsRequestedPort(t *testing.T) {
	legitimate := testUDPSocket(t, "127.0.0.1")
	session := newUDPAssociationTest(t, socks5.Request{
		Command: 3, Address: "127.0.0.1", Port: uint16(legitimate.LocalAddr().(*net.UDPAddr).Port),
	})
	wrongPort := testUDPSocket(t, "127.0.0.1")
	packet := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "example.test", Port: 53}, []byte("port-check"))
	if _, err := wrongPort.WriteToUDP(packet, session.relay); err != nil {
		t.Fatal(err)
	}
	_ = wrongPort.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := wrongPort.ReadFromUDP(make([]byte, 100)); err == nil {
		t.Fatal("unrequested source port received a response")
	}
	if _, err := legitimate.WriteToUDP(packet, session.relay); err != nil {
		t.Fatal(err)
	}
	_ = legitimate.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 100)
	n, _, err := legitimate.ReadFromUDP(buffer)
	if err != nil || !bytes.Equal(buffer[:n], packet) {
		t.Fatalf("requested source port failed: %v", err)
	}
}

func TestUDPAssociationStopsWhenRemoteCloses(t *testing.T) {
	session := newUDPAssociationTest(t, socks5.Request{Command: 3, Address: "0.0.0.0"})
	_ = session.remote.Close()
	select {
	case <-session.done:
	case <-time.After(time.Second):
		t.Fatal("remote closure did not stop idle association and all its workers")
	}
}

func TestUDPAssociationStopsWhenRemoteHalfClosesDuringTraffic(t *testing.T) {
	session := newUDPAssociationTest(t, socks5.Request{Command: 3, Address: "0.0.0.0"})
	sender := testUDPSocket(t, "127.0.0.1")
	packet := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "192.0.2.1", Port: 53}, []byte("active"))
	sendingDone := make(chan struct{})
	stopSending := make(chan struct{})
	go func() {
		defer close(sendingDone)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_, _ = sender.WriteToUDP(packet, session.relay)
			case <-stopSending:
				return
			}
		}
	}()
	defer func() { close(stopSending); <-sendingDone }()
	if err := session.remote.(*tls.Conn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.done:
	case <-time.After(time.Second):
		t.Fatal("incoming UDP traffic kept a remotely closed association alive")
	}
}
