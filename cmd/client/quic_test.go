package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/quicudp"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
)

func TestOpenRemoteQUICReportsAuthRejectionWithoutStreamReply(t *testing.T) {
	source := httptest.NewTLSServer(nil)
	cert := source.TLS.Certificates[0]
	source.Close()
	serverResources := datagram.NewResources(4, 1<<20)
	defer serverResources.Close()
	ln, err := quicudp.Listen("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{quicudp.ALPN}}, serverResources, time.Second, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = tunnel.ReadLine(bufio.NewReader(conn))
		// No ERR reply: the close code must carry the authentication outcome.
		conn.(*quicudp.Conn).RejectAuthentication()
	}()
	resources := datagram.NewResources(2, 1<<20)
	defer resources.Close()
	pin := sha256.Sum256(cert.Certificate[0])
	cfg := &config.ClientConfig{RemoteAddr: ln.Addr().String(), AuthToken: "wrong-token", CertificateFingerprint: hex.EncodeToString(pin[:]), UDPTransport: "quic"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	session, err := openRemoteUDP(ctx, cfg, nil, resources)
	if !errors.Is(err, errAuthRejected) || session.Stage != "auth" || session.Conn != nil {
		t.Fatalf("authentication result: stage=%s err=%v", session.Stage, err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("authentication server did not close")
	}
	if s := resources.Stats(); s.Sockets != 0 || s.BufferBytes != s.CachedBytes {
		t.Fatal("rejection leaked client resources", s)
	}
}

func TestQUICUDPAssociationPreservesSourceAndControlLifetime(t *testing.T) {
	certSource := httptest.NewTLSServer(nil)
	cert := certSource.TLS.Certificates[0]
	certSource.Close()
	serverResources := datagram.NewResources(8, 4<<20)
	defer serverResources.Close()
	listener, err := quicudp.Listen("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{quicudp.ALPN}}, serverResources, time.Second, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	remoteDone := make(chan struct{})
	remoteErrors := make(chan error, 1)
	go func() {
		defer close(remoteDone)
		conn, err := listener.Accept()
		if err != nil {
			remoteErrors <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		reader := bufio.NewReader(conn)
		for _, want := range []string{"AUTH test-token", "UDP"} {
			line, err := tunnel.ReadLine(reader)
			if err != nil || line != want {
				remoteErrors <- err
				return
			}
			if want == "UDP" {
				tunnel.EnableDatagrams(conn)
			}
			if err := tunnel.SendOK(conn); err != nil {
				remoteErrors <- err
				return
			}
		}
		_ = conn.SetDeadline(time.Time{})
		packets := conn.(*quicudp.Conn)
		for {
			p, err := packets.ReadPacket()
			if err != nil {
				return
			}
			err = packets.WritePacket(p.Data)
			p.Release()
			if err != nil {
				remoteErrors <- err
				return
			}
		}
	}()
	local, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	control, err := net.Dial("tcp4", local.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	clientConn, err := local.Accept()
	if err != nil {
		t.Fatal(err)
	}
	clientResources := datagram.NewResources(4, 4<<20)
	defer clientResources.Close()
	pin := sha256.Sum256(cert.Certificate[0])
	cfg := &config.ClientConfig{RemoteAddr: listener.Addr().String(), AuthToken: "test-token", CertificateFingerprint: hex.EncodeToString(pin[:]), UDPTransport: "quic", UDPQueueConfig: config.UDPQueueConfig{UDPQueueMaxAgeMS: 1000}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer clientConn.Close()
		handleUDPAssociate(context.Background(), clientConn, socks5.Request{Command: 3, Address: "0.0.0.0"}, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Now(), func() {}, nil, clientResources)
	}()
	t.Cleanup(func() {
		_ = control.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("QUIC association did not close after SOCKS control disconnect")
		}
		_ = listener.Close()
		select {
		case <-remoteDone:
		case <-time.After(3 * time.Second):
			t.Error("remote QUIC worker did not stop")
		}
	})
	_ = control.SetReadDeadline(time.Now().Add(3 * time.Second))
	var reply [10]byte
	if _, err := io.ReadFull(control, reply[:]); err != nil || reply[1] != 0 {
		t.Fatalf("association reply %v: %v", reply, err)
	}
	relay := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(binary.BigEndian.Uint16(reply[8:]))}
	foreign, valid := testUDPSocket(t, "127.0.0.2"), testUDPSocket(t, "127.0.0.1")
	packet := socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "example.test", Port: 53}, []byte("foreign"))
	_, _ = foreign.WriteToUDP(packet, relay)
	_, _ = valid.WriteToUDP([]byte{0, 0}, relay)
	buf := make([]byte, 65536)
	for _, size := range []int{0, 64, 1400, 60000} {
		packet = socks5.BuildUDPDatagram(socks5.UDPDatagram{Host: "example.test", Port: 53}, bytes.Repeat([]byte{byte(size + 1)}, size))
		if _, err := valid.WriteToUDP(packet, relay); err != nil {
			t.Fatal(err)
		}
		_ = valid.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := valid.ReadFromUDP(buf)
		if err != nil || !bytes.Equal(packet, buf[:n]) {
			t.Fatalf("UDP payload %d changed: n=%d err=%v", size, n, err)
		}
	}
	_ = foreign.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, _, err := foreign.ReadFromUDP(buf); err == nil {
		t.Fatal("foreign UDP source received a response")
	}
	_ = control.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("client QUIC cleanup timeout")
	}
	select {
	case <-remoteDone:
	case <-time.After(3 * time.Second):
		t.Fatal("remote QUIC cleanup timeout")
	}
	select {
	case err := <-remoteErrors:
		t.Fatalf("remote QUIC error: %v", err)
	default:
	}
	if s := clientResources.Stats(); s.Sockets != 0 || s.BufferBytes != s.CachedBytes {
		t.Fatal("client retained resources", s)
	}
}
