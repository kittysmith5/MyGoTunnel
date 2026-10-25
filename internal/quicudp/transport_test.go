package quicudp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mygotunnel/internal/datagram"
)

func transportCertificate(t testing.TB) (tls.Certificate, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "quic.test"},
		DNSNames: []string{"quic.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	sha := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, hex.EncodeToString(sha[:]), roots
}

type transportPair struct {
	client, server *Conn
	listener       net.Listener
	resources      *datagram.Resources
}

func newTransportPair(t *testing.T, maxAge time.Duration, route ...func(string) string) transportPair {
	t.Helper()
	return newTransportPairProtocols(t, maxAge, []string{ALPN}, Protocols(), route...)
}

func newTransportPairProtocols(t *testing.T, maxAge time.Duration, serverProtocols, clientProtocols []string, route ...func(string) string) transportPair {
	t.Helper()
	cert, pin, _ := transportCertificate(t)
	resources := datagram.NewResources(16, 8<<20)
	ln, err := Listen("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: serverProtocols}, resources, maxAge, 8)
	if err != nil {
		resources.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); resources.Close() })
	accepted := make(chan *Conn, 1)
	failed := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			failed <- err
			return
		}
		accepted <- c.(*Conn)
	}()
	dialAddr := ln.Addr().String()
	if len(route) != 0 {
		dialAddr = route[0](dialAddr)
	}
	cfg, err := ClientTLSConfig(dialAddr, "quic.test", pin)
	if err != nil {
		t.Fatal(err)
	}
	cfg.NextProtos = clientProtocols
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, err := Dial(ctx, dialAddr, cfg, resources, maxAge)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	var server *Conn
	select {
	case server = <-accepted:
	case err := <-failed:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	t.Cleanup(func() { server.Close() })
	return transportPair{client, server, ln, resources}
}

func authorizePair(t *testing.T, p transportPair) {
	t.Helper()
	if err := p.client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := p.server.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(p.client, "AUTH placeholder\nUDP\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(p.server)
	for _, expected := range []string{"AUTH placeholder\n", "UDP\n"} {
		line, err := reader.ReadString('\n')
		if err != nil || line != expected {
			t.Fatalf("control %q: %v", line, err)
		}
	}
	p.server.EnableDatagrams()
	if _, err := io.WriteString(p.server, "OK\nOK\n"); err != nil {
		t.Fatal(err)
	}
	reader = bufio.NewReader(p.client)
	for i := 0; i < 2; i++ {
		line, err := reader.ReadString('\n')
		if err != nil || line != "OK\n" {
			t.Fatalf("reply %q: %v", line, err)
		}
	}
	if err := p.client.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := p.server.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	p.client.EnableDatagrams()
}

func TestTransportControlAndDatagrams(t *testing.T) {
	p := newTransportPair(t, 250*time.Millisecond)
	if err := p.client.WritePacket([]byte("unauthorized")); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("before auth: %v", err)
	}
	if _, err := p.server.ReadPacket(); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("before auth read: %v", err)
	}
	authorizePair(t, p)
	for _, size := range []int{1, 64, 1400, 60000, 65000} {
		payload := bytes.Repeat([]byte{byte(size)}, size)
		for _, direction := range [][2]*Conn{{p.client, p.server}, {p.server, p.client}} {
			if err := direction[0].SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := direction[1].SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := direction[0].WritePacket(payload); err != nil {
				t.Fatal(err)
			}
			packet, err := direction[1].ReadPacket()
			if err != nil {
				t.Fatalf("size %d: %v", size, err)
			}
			if !bytes.Equal(packet.Data, payload) {
				t.Fatalf("size %d mismatch", size)
			}
			packet.Release()
		}
	}
}

func TestTransportPreAuthDatagramsDiscarded(t *testing.T) {
	p := newTransportPair(t, time.Second)
	fragments, err := Fragments([]byte("must not forward"), 777)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.client.q.SendDatagram(fragments[0]); err != nil {
		t.Fatal(err)
	}
	limit := time.Now().Add(time.Second)
	for p.server.PreAuthDrops() == 0 && time.Now().Before(limit) {
		time.Sleep(time.Millisecond)
	}
	if p.server.PreAuthDrops() == 0 {
		t.Fatal("pre-auth packet not drained")
	}
	authorizePair(t, p)
	if err := p.client.WritePacket([]byte("authorized")); err != nil {
		t.Fatal(err)
	}
	if err := p.server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	packet, err := p.server.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Release()
	if string(packet.Data) != "authorized" {
		t.Fatal("pre-auth payload escaped")
	}
}

func TestTransportReassemblyIndependentOfQueueAge(t *testing.T) {
	p := newTransportPair(t, 20*time.Millisecond)
	authorizePair(t, p)
	payload := bytes.Repeat([]byte("x"), 1400)
	fragments, err := Fragments(payload, 888)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.client.q.SendDatagram(fragments[0]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := p.client.q.SendDatagram(fragments[1]); err != nil {
		t.Fatal(err)
	}
	if err := p.server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	packet, err := p.server.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Release()
	if !bytes.Equal(packet.Data, payload) {
		t.Fatal("reassembly mismatch")
	}
}

func TestTransportControlFINEndsAssociation(t *testing.T) {
	p := newTransportPair(t, time.Second)
	authorizePair(t, p)
	if err := p.client.stream.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err := p.server.ReadPacket()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("FIN: %v", err)
	}
	p.server.Close()
	p.client.Close()
	p.listener.Close()
	limit := time.Now().Add(time.Second)
	for p.resources.Stats().Sockets != 0 && time.Now().Before(limit) {
		time.Sleep(time.Millisecond)
	}
	if p.resources.Stats().Sockets != 0 {
		t.Fatal("UDP sockets not released")
	}
	stats := p.resources.Stats()
	if stats.BufferBytes != stats.CachedBytes {
		t.Fatalf("live packet leak: %+v", stats)
	}
}

func TestTransportPeerCloseIsNormalEOF(t *testing.T) {
	p := newTransportPair(t, time.Second)
	authorizePair(t, p)
	p.client.Close()
	if err := p.server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err := p.server.ReadPacket()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("peer close: %v", err)
	}
}

func TestTransportDeadlinesAndClose(t *testing.T) {
	t.Run("lazy stream", func(t *testing.T) {
		p := newTransportPair(t, time.Second)
		if err := p.server.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		var one [1]byte
		_, err := p.server.Read(one[:])
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("lazy stream timeout: %v", err)
		}
	})
	t.Run("packet write", func(t *testing.T) {
		p := newTransportPair(t, time.Second)
		authorizePair(t, p)
		if err := p.client.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		if err := p.client.WritePacket([]byte("x")); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("write timeout: %v", err)
		}
	})
	t.Run("packet read interrupted", func(t *testing.T) {
		p := newTransportPair(t, time.Second)
		authorizePair(t, p)
		result := make(chan error, 1)
		go func() { _, err := p.server.ReadPacket(); result <- err }()
		p.server.Close()
		select {
		case err := <-result:
			if err == nil {
				t.Fatal("read succeeded")
			}
		case <-time.After(time.Second):
			t.Fatal("close did not interrupt read")
		}
	})
}

func TestTransportCertificateTrust(t *testing.T) {
	cert, pin, roots := transportCertificate(t)
	resources := datagram.NewResources(16, 1<<20)
	defer resources.Close()
	ln, err := Listen("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{ALPN}}, resources, time.Second, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for _, tc := range []struct {
		name, pin, sni string
		roots          *x509.CertPool
		good           bool
	}{
		{"pin", pin, "quic.test", nil, true},
		{"wrong pin", strings.Repeat("00", 32), "quic.test", nil, false},
		{"CA", "", "quic.test", roots, true},
		{"wrong hostname", "", "other.test", roots, false},
		{"untrusted CA", "", "quic.test", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ClientTLSConfig(ln.Addr().String(), tc.sni, tc.pin)
			if err != nil {
				t.Fatal(err)
			}
			cfg.RootCAs = tc.roots
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := Dial(ctx, ln.Addr().String(), cfg, resources, time.Second)
			if conn != nil {
				defer conn.Close()
			}
			if (err == nil) != tc.good {
				t.Fatalf("trust success=%v: %v", tc.good, err)
			}
			if conn != nil && conn.q.ConnectionState().TLS.NegotiatedProtocol != ALPN {
				t.Fatal("wrong ALPN")
			}
		})
	}
}

func TestTransportMissingFragmentsDoNotBlockNewPackets(t *testing.T) {
	p := newTransportPair(t, time.Second)
	authorizePair(t, p)
	partial, err := Fragments(bytes.Repeat([]byte("x"), 60000), 999)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.client.q.SendDatagram(partial[0]); err != nil {
		t.Fatal(err)
	}
	if err := p.client.q.SendDatagram([]byte("malformed")); err != nil {
		t.Fatal(err)
	}
	if err := p.client.WritePacket([]byte("new packet")); err != nil {
		t.Fatal(err)
	}
	if err := p.server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	packet, err := p.server.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Release()
	if string(packet.Data) != "new packet" {
		t.Fatal("old fragment blocked later packet")
	}
	if p.server.malformedDrops.Load() != 1 {
		t.Fatal("malformed fragment not counted")
	}
}

func TestTransportConcurrentEnableAndClose(t *testing.T) {
	for i := 0; i < 8; i++ {
		p := newTransportPair(t, time.Second)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); p.client.EnableDatagrams() }()
		go func() { defer wg.Done(); p.client.Close() }()
		wg.Wait()
	}
}

func TestTransportBlockedSendDeadline(t *testing.T) {
	var blackhole atomic.Bool
	route := func(serverAddr string) string {
		server, err := net.ResolveUDPAddr("udp", serverAddr)
		if err != nil {
			t.Fatal(err)
		}
		proxy, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			var client *net.UDPAddr
			buffer := make([]byte, 65536)
			for {
				n, from, err := proxy.ReadFromUDP(buffer)
				if err != nil {
					return
				}
				if blackhole.Load() {
					continue
				}
				if from.Port == server.Port && from.IP.Equal(server.IP) && from.Zone == server.Zone {
					if client != nil {
						_, _ = proxy.WriteToUDP(buffer[:n], client)
					}
				} else {
					client = from
					_, _ = proxy.WriteToUDP(buffer[:n], server)
				}
			}
		}()
		t.Cleanup(func() { proxy.Close(); <-done })
		return proxy.LocalAddr().String()
	}
	p := newTransportPair(t, time.Second, route)
	authorizePair(t, p)
	// Freeze both directions after a real authenticated handshake. QUIC can
	// transmit its remaining congestion window, then its 32-DATAGRAM send queue
	// fills because no ACKs return. This tests the blocking library call itself.
	blackhole.Store(true)
	deadline := time.Now().Add(100 * time.Millisecond)
	if err := p.client.SetWriteDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		payload := bytes.Repeat([]byte("x"), 60000)
		for i := 0; i < 64; i++ {
			if err := p.client.WritePacket(payload); err != nil {
				result <- err
				return
			}
		}
		result <- nil
	}()
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("blocked write: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked SendDatagram did not exit")
	}
	if !errors.Is(p.client.failure(), os.ErrDeadlineExceeded) {
		t.Fatalf("timer did not interrupt active SendDatagram: %v", p.client.failure())
	}
	if sent := p.client.fragmentEnqueues.Load(); sent < 32 || sent >= 64*56 {
		t.Fatalf("expected bounded filled send queue, enqueued %d", sent)
	}
	closed := make(chan struct{})
	go func() { p.client.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("close deadlocked after write timeout")
	}
}

func TestTransportExplicitCloseCodes(t *testing.T) {
	t.Run("auth before enable", func(t *testing.T) {
		p := newTransportPair(t, time.Second)
		if _, err := io.WriteString(p.client, "AUTH placeholder\nUDP\n"); err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(p.server)
		if _, err := reader.ReadString('\n'); err != nil {
			t.Fatal(err)
		}
		p.server.RejectAuthentication()
		var one [1]byte
		_, err := p.client.Read(one[:])
		if !errors.Is(err, ErrAuthRejected) {
			t.Fatalf("auth close: %v", err)
		}
	})
	t.Run("auth packet read", func(t *testing.T) {
		p := newTransportPair(t, time.Second)
		authorizePair(t, p)
		p.server.RejectAuthentication()
		_, err := p.client.ReadPacket()
		if !errors.Is(err, ErrAuthRejected) {
			t.Fatalf("auth packet close: %v", err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		p := newTransportPair(t, time.Second)
		authorizePair(t, p)
		p.server.fail(os.ErrDeadlineExceeded)
		_, err := p.client.ReadPacket()
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("timeout close: %v", err)
		}
	})
	t.Run("protocol", func(t *testing.T) {
		p := newTransportPair(t, time.Second)
		authorizePair(t, p)
		p.server.fail(errControlProtocol)
		_, err := p.client.ReadPacket()
		if err == nil || errors.Is(err, io.EOF) {
			t.Fatalf("protocol close: %v", err)
		}
	})
}
