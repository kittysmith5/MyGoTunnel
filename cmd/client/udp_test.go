package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
)

type udpAssociationTest struct {
	control net.Conn
	remote  net.Conn
	relay   *net.UDPAddr
	done    <-chan struct{}
	logs    *bytes.Buffer
}

// Exercise the real uTLS connection and TCP peer addresses without using an
// external server. The remote stub echoes framed SOCKS UDP packets unchanged.
func newUDPAssociationTest(t *testing.T, request socks5.Request, limits ...*datagram.Resources) udpAssociationTest {
	t.Helper()
	return newUDPAssociationTestReply(t, request, 0, net.DefaultResolver.LookupIPAddr, limits...)
}

func newUDPAssociationTestReply(t *testing.T, request socks5.Request, wantRep byte, lookup udpSourceLookup, limits ...*datagram.Resources) udpAssociationTest {
	return newUDPAssociationTestConfig(t, request, wantRep, lookup, nil, limits...)
}

func newUDPAssociationTestConfig(t *testing.T, request socks5.Request, wantRep byte, lookup udpSourceLookup, options *config.ClientConfig, limits ...*datagram.Resources) udpAssociationTest {
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
	logs := new(bytes.Buffer)
	cfg := new(config.ClientConfig)
	if options != nil {
		*cfg = *options
	}
	pin := sha256.Sum256(cert.Certificate[0])
	cfg.RemoteAddr, cfg.AuthToken, cfg.CertificateFingerprint = listener.Addr().String(), "test-token", hex.EncodeToString(pin[:])
	go func() {
		defer close(done)
		defer clientConn.Close()
		handleUDPAssociateWithResolver(context.Background(), clientConn, request, cfg, slog.New(slog.NewTextHandler(logs, nil)), time.Now(), func() {}, nil, lookup, limits...)
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
	if reply[0] != 5 || reply[1] != wantRep || reply[3] != 1 {
		t.Fatalf("UDP association reply: %v", reply)
	}
	if wantRep != 0 {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("rejected association did not stop")
		}
		select {
		case <-remoteConn:
			t.Fatal("rejected UDP source opened remote connection")
		default:
		}
		return udpAssociationTest{control: control, done: done, logs: logs}
	}
	return udpAssociationTest{
		control: control, remote: <-remoteConn, done: done, logs: logs,
		relay: &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(binary.BigEndian.Uint16(reply[8:]))},
	}
}

func TestUDPAssociationReturnsAllManagedBuffers(t *testing.T) {
	resources := datagram.NewResources(1, 1<<20)
	defer resources.Close()
	session := newUDPAssociationTest(t, socks5.Request{Command: 3, Address: "0.0.0.0"}, resources)
	sender := testUDPSocket(t, "127.0.0.1")
	packet := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "example.test", Port: 53}, []byte("pooled"))
	for i := 0; i < 10; i++ {
		if _, err := sender.WriteToUDP(packet, session.relay); err != nil {
			t.Fatal(err)
		}
		sender.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 100)
		if n, _, err := sender.ReadFromUDP(buf); err != nil || !bytes.Equal(buf[:n], packet) {
			t.Fatal(err)
		}
	}
	session.control.Close()
	select {
	case <-session.done:
	case <-time.After(time.Second):
		t.Fatal("association cleanup timeout")
	}
	if s := resources.Stats(); s.Sockets != 0 || s.BufferBytes != s.CachedBytes || s.PeakBytes > 1<<20 {
		t.Fatal(s)
	}
	resources.Close()
	if s := resources.Stats(); s.BufferBytes != 0 {
		t.Fatal(s)
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
	}{
		{foreign, packet},
		{malformed, []byte{0, 0, 1, 1}},
		{malformed, oversized},
		{malformed, socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "", Port: 53}, nil)},
		{malformed, socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "bad\nhost", Port: 53}, nil)},
		{malformed, socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "bad:host", Port: 53}, nil)},
		{malformed, socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "example.test", Port: 0}, nil)},
	} {
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
