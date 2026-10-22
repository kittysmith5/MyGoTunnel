package preconnect

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestPoolCloseDoesNotWriteTLSNotifyOnBackpressuredStandbys(t *testing.T) {
	certSource := httptest.NewTLSServer(nil)
	cert := certSource.TLS.Certificates[0]
	certSource.Close()
	var peersMu sync.Mutex
	var peers []net.Conn
	closePeers := func() {
		peersMu.Lock()
		defer peersMu.Unlock()
		for _, peer := range peers {
			peer.Close()
		}
	}
	defer closePeers()
	p, err := New(Options{Size: 2, MaxSize: 2, IdleTTL: time.Hour}, func(ctx context.Context) (*Entry, error) {
		a, b := net.Pipe()
		peersMu.Lock()
		peers = append(peers, b)
		peersMu.Unlock()
		server := tls.Server(b, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
		serverDone := make(chan error, 1)
		go func() { serverDone <- server.HandshakeContext(ctx) }() // stop reading after handshake
		client := utls.UClient(a, &utls.Config{InsecureSkipVerify: true, MinVersion: utls.VersionTLS12, MaxVersion: utls.VersionTLS12}, utls.HelloGolang)
		if err := client.HandshakeContext(ctx); err != nil {
			a.Close()
			return nil, err
		}
		if err := <-serverDone; err != nil {
			a.Close()
			return nil, err
		}
		return &Entry{Conn: client, Reader: bufio.NewReader(client)}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	idle(t, p, 2)
	done := make(chan struct{})
	go func() { p.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		closePeers() // release the broken implementation before reporting failure
		<-done
		t.Fatal("unused TLS cleanup waited for close_notify writes")
	}
}
