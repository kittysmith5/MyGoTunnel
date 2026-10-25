package quicudp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"mygotunnel/internal/datagram"
)

func testTokenStore(t *testing.T, base quic.TokenStore, remote, sni, policy string) quic.TokenStore {
	t.Helper()
	config := &tls.Config{ServerName: sni}
	if strings.HasPrefix(policy, "pin:") {
		config.InsecureSkipVerify = true
		config.VerifyConnection = func(tls.ConnectionState) error { return nil }
	}
	store, err := addressTokensFor(remote, config, []DialOptions{{TokenCache: true, TokenTrustScope: policy}})
	if err != nil {
		t.Fatal(err)
	}
	scoped, ok := store.(scopedAddressTokens)
	if !ok {
		t.Fatal("scoped token store missing")
	}
	scoped.store = base
	return scoped
}

func TestAddressTokenCacheBoundsAndSingleUse(t *testing.T) {
	base := quic.NewLRUTokenStore(16, 4)
	store := testTokenStore(t, base, "node.invalid:443", "node.invalid", "ca:")
	var tokens [5]*quic.ClientToken
	for i := range tokens {
		tokens[i] = new(quic.ClientToken)
		store.Put("node.invalid", tokens[i])
	}
	for i := 4; i > 0; i-- {
		if got := store.Pop("node.invalid"); got != tokens[i] {
			t.Fatalf("bounded token %d changed or reused", i)
		}
	}
	if store.Pop("node.invalid") != nil {
		t.Fatal("evicted fifth token remained or a token was reused")
	}
	stores := make([]quic.TokenStore, 17)
	for i := range stores {
		stores[i] = testTokenStore(t, base, fmt.Sprintf("node-%d.invalid:443", i), "node.invalid", "ca:")
		stores[i].Put("node.invalid", new(quic.ClientToken))
	}
	if stores[0].Pop("node.invalid") != nil {
		t.Fatal("cache retained more than 16 endpoint scopes")
	}
	for _, store := range stores[1:] {
		if store.Pop("node.invalid") == nil || store.Pop("node.invalid") != nil {
			t.Fatal("remaining endpoint token missing or handed out twice")
		}
	}
}

func TestAddressTokenCacheTrustAndEndpointIsolation(t *testing.T) {
	base := quic.NewLRUTokenStore(16, 4)
	pin := strings.Repeat("ab", 32)
	original := testTokenStore(t, base, "node.invalid:443", "sni.invalid", "pin:"+pin)
	token := new(quic.ClientToken)
	original.Put("sni.invalid", token)
	for _, tc := range []struct{ remote, sni, policy string }{
		{"other.invalid:443", "sni.invalid", "pin:" + pin},
		{"node.invalid:8443", "sni.invalid", "pin:" + pin},
		{"node.invalid:443", "other.invalid", "pin:" + pin},
		{"node.invalid:443", "sni.invalid", "pin:" + strings.Repeat("cd", 32)},
		{"node.invalid:443", "sni.invalid", "ca:"},
	} {
		store := testTokenStore(t, base, tc.remote, tc.sni, tc.policy)
		if store.Pop("sni.invalid") != nil {
			t.Fatal("token crossed endpoint, SNI or certificate trust policy")
		}
	}
	canonical := testTokenStore(t, base, "node.invalid:443", "sni.invalid", "pin:"+strings.ToUpper(pin))
	if canonical.Pop("sni.invalid") != token || original.Pop("sni.invalid") != nil {
		t.Fatal("pin canonicalization changed or token was reused")
	}
}

func TestAddressTokenCacheConcurrentSingleUse(t *testing.T) {
	base := quic.NewLRUTokenStore(16, 4)
	store := testTokenStore(t, base, "node.invalid:443", "node.invalid", "ca:")
	var seen sync.Map
	var repeated atomic.Bool
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 500 {
				store.Put("node.invalid", new(quic.ClientToken))
				if token := store.Pop("node.invalid"); token != nil {
					if _, loaded := seen.LoadOrStore(token, true); loaded {
						repeated.Store(true)
					}
				}
			}
		}()
	}
	workers.Wait()
	if repeated.Load() {
		t.Fatal("the same source-address token was handed to two dialers")
	}
}

func TestAddressTokenCacheRequiresExplicitValidTrust(t *testing.T) {
	config := &tls.Config{ServerName: "node.invalid"}
	if store, err := addressTokensFor("node.invalid:443", config, nil); err != nil || store != nil {
		t.Fatal("legacy callers unexpectedly acquired a token cache", err)
	}
	for _, policy := range []string{"", "ca", "ca:unexpected", "pin:", "pin:" + strings.Repeat("00", 32)} {
		if _, err := addressTokensFor("node.invalid:443", config, []DialOptions{{TokenCache: true, TokenTrustScope: policy}}); err == nil {
			t.Fatalf("invalid trust policy accepted: %q", policy)
		}
	}
	customRoots := config.Clone()
	customRoots.RootCAs = x509.NewCertPool()
	if store, err := addressTokensFor("node.invalid:443", customRoots, []DialOptions{{TokenCache: true, TokenTrustScope: "ca:"}}); err != nil || store != nil {
		t.Fatal("custom root pool was implicitly grouped with system trust", err)
	}
	if config := transportConfig(); config.TokenStore != nil || config.Allow0RTT {
		t.Fatal("source token optimization changed server/legacy defaults or enabled 0-RTT")
	}
}

type addressTokenTestServer struct {
	listener *quic.Listener
	resource *datagram.Resources
	retries  atomic.Uint64
	pin      string
}

func newAddressTokenTestServer(t *testing.T, maxTokenAge time.Duration) *addressTokenTestServer {
	t.Helper()
	cert, pin, _ := transportCertificate(t)
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	s := &addressTokenTestServer{pin: pin, resource: datagram.NewResources(8, 8<<20)}
	transport := &quic.Transport{Conn: udp, MaxTokenAge: maxTokenAge, VerifySourceAddress: func(net.Addr) bool {
		s.retries.Add(1)
		return true
	}}
	s.listener, err = transport.Listen(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13,
		NextProtos: []string{ALPN}, SessionTicketsDisabled: true}, transportConfig())
	if err != nil {
		transport.Close()
		udp.Close()
		s.resource.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.listener.Close()
		transport.Close()
		udp.Close()
		s.resource.Close()
	})
	return s
}

func (s *addressTokenTestServer) pair(t *testing.T) transportPair {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	accepted := make(chan *quic.Conn, 1)
	failure := make(chan error, 1)
	go func() {
		conn, err := s.listener.Accept(ctx)
		if err != nil {
			failure <- err
			return
		}
		accepted <- conn
	}()
	addr := s.listener.Addr().String()
	config, err := ClientTLSConfig(addr, "quic.test", s.pin)
	if err != nil {
		t.Fatal(err)
	}
	client, err := Dial(ctx, addr, config, s.resource, time.Second, DialOptions{TokenCache: true, TokenTrustScope: "pin:" + s.pin})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	var raw *quic.Conn
	select {
	case raw = <-accepted:
	case err := <-failure:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	server, err := newConn(raw, nil, s.resource, time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return transportPair{client: client, server: server, resources: s.resource}
}

func (s *addressTokenTestServer) waitForToken(t *testing.T) {
	t.Helper()
	config, err := ClientTLSConfig(s.listener.Addr().String(), "quic.test", s.pin)
	if err != nil {
		t.Fatal(err)
	}
	store, err := addressTokensFor(s.listener.Addr().String(), config, []DialOptions{{TokenCache: true, TokenTrustScope: "pin:" + s.pin}})
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		if token := store.Pop("quic.test"); token != nil {
			// This test only observed the token, without presenting it on the
			// network. Return it so the next fresh connection consumes it once.
			store.Put("quic.test", token)
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("server NEW_TOKEN was not received independently of TLS session tickets")
}

func TestAddressTokensAvoidRepeatedRetryWithoutResumptionOrAuthBypass(t *testing.T) {
	s := newAddressTokenTestServer(t, 0)
	first := s.pair(t)
	authorizePair(t, first)
	s.waitForToken(t)
	firstRetries := s.retries.Load()
	if firstRetries == 0 {
		t.Fatal("first new connection skipped required source-address Retry")
	}
	second := s.pair(t)
	if after := s.retries.Load(); after != firstRetries {
		t.Fatalf("second fresh connection repeated Retry: before=%d after=%d", firstRetries, after)
	}
	if first.client.LocalAddr().String() == second.client.LocalAddr().String() {
		t.Fatal("test did not create a fresh UDP socket")
	}
	if state := second.client.q.ConnectionState(); state.TLS.DidResume || state.Used0RTT || !state.TLS.HandshakeComplete {
		t.Fatal("address token changed the full TLS handshake or enabled 0-RTT")
	}
	if err := second.client.WritePacket([]byte("before AUTH")); !errors.Is(err, ErrNotAuthorized) {
		t.Fatal("cached source token authorized application data", err)
	}
	// Every new connection still performs the complete AUTH/UDP exchange.
	authorizePair(t, second)
	s.waitForToken(t)
	config, err := ClientTLSConfig(s.listener.Addr().String(), "quic.test", strings.Repeat("00", 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	beforeSockets := s.resource.Stats().Sockets
	// Deliberately select the warm token bucket while changing the certificate
	// verifier. Even an incorrectly declared caller scope cannot bypass TLS.
	conn, err := Dial(ctx, s.listener.Addr().String(), config, s.resource, time.Second,
		DialOptions{TokenCache: true, TokenTrustScope: "pin:" + s.pin})
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("cached address token bypassed certificate pin verification")
	}
	if s.retries.Load() != firstRetries {
		t.Fatal("wrong-pin attempt did not exercise an otherwise valid cached address token")
	}
	if s.resource.Stats().Sockets != beforeSockets {
		t.Fatal("wrong-pin cached attempt leaked a socket reservation")
	}
	t.Logf("Retry callbacks first=%d, warm=%d; two complete AUTH exchanges; TLS resume=false, 0-RTT=false; wrong pin rejected", firstRetries, s.retries.Load()-firstRetries)
}

func TestExpiredAddressTokenStillRequiresRetry(t *testing.T) {
	s := newAddressTokenTestServer(t, time.Nanosecond)
	first := s.pair(t)
	authorizePair(t, first)
	s.waitForToken(t)
	before := s.retries.Load()
	second := s.pair(t)
	if s.retries.Load() <= before {
		t.Fatal("expired source token bypassed required Retry validation")
	}
	authorizePair(t, second)
}
