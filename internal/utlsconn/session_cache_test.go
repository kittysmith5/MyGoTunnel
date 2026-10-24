package utlsconn

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"mygotunnel/internal/config"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func sessionFixture(t testing.TB, version uint16) (string, string, *x509.CertPool) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.json")
	if _, err := config.InitializeServer(path, "localhost:8443", ":8443"); err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.LoadServerConfig(path)
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	pin := sha256.Sum256(leaf.Raw)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: version, MaxVersion: version, NextProtos: []string{"http/1.1"}}
	var workers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(5 * time.Second))
				conn := tls.Server(raw, c)
				if conn.Handshake() == nil {
					io.WriteString(conn, "ok")
				}
			}()
		}
	}()
	t.Cleanup(func() { ln.Close(); <-done; workers.Wait() })
	return ln.Addr().String(), hex.EncodeToString(pin[:]), roots
}

func sessionRoundTrip(addr, sni, pin string, enabled bool, roots *x509.CertPool, cache utls.ClientSessionCache) (DialTimings, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, timings, err := dialWithOptions(ctx, addr, sni, pin, Options{SessionCache: enabled}, roots, cache)
	if err != nil {
		return timings, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	// Reading application data also processes TLS 1.3 NewSessionTicket.
	_, err = io.ReadFull(c, make([]byte, 2))
	return timings, err
}

func TestSessionResumptionAndTrustIsolation(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, mode := range []string{"pin", "ca"} {
			t.Run(tls.VersionName(version)+"/"+mode, func(t *testing.T) {
				addr, pin, roots := sessionFixture(t, version)
				if mode == "ca" {
					pin = ""
				}
				cache := utls.NewLRUClientSessionCache(64)
				for i := 0; i < 3; i++ {
					timings, err := sessionRoundTrip(addr, "localhost", pin, true, roots, cache)
					if err != nil || timings.TLSResumed != (i > 0) {
						t.Fatalf("handshake %d resumed=%v: %v", i, timings.TLSResumed, err)
					}
				}
				if timings, err := sessionRoundTrip(addr, "localhost", pin, false, roots, cache); err != nil || timings.TLSResumed {
					t.Fatalf("disabled cache: %v", err)
				}
				if _, err := sessionRoundTrip(addr, "localhost", strings.Repeat("00", 32), true, roots, cache); err == nil {
					t.Fatal("changed pin accepted")
				}
				if mode == "ca" {
					if _, err := sessionRoundTrip(addr, "localhost", "", true, x509.NewCertPool(), cache); err == nil {
						t.Fatal("resumed certificate accepted after roots changed")
					}
					if _, err := sessionRoundTrip(addr, "wrong.example", "", true, roots, cache); err == nil {
						t.Fatal("wrong CA hostname accepted")
					}
				} else {
					if timings, err := sessionRoundTrip(addr, "other.example", pin, true, roots, cache); err != nil || timings.TLSResumed {
						t.Fatalf("SNI cache isolation: %v", err)
					}
				}
				_, port, _ := net.SplitHostPort(addr)
				if timings, err := sessionRoundTrip(net.JoinHostPort("localhost", port), "localhost", pin, true, roots, cache); err != nil || timings.TLSResumed {
					t.Fatalf("endpoint cache isolation: %v", err)
				}
			})
		}
	}
}

// Deliberately ignores the caller's namespace to force a resumed connection
// under a different pin. VerifyConnection must still reject the cached identity.
type fixedCache struct{ utls.ClientSessionCache }

func (f fixedCache) Get(string) (*utls.ClientSessionState, bool) {
	return f.ClientSessionCache.Get("fixed")
}
func (f fixedCache) Put(_ string, s *utls.ClientSessionState) { f.ClientSessionCache.Put("fixed", s) }

func TestResumedPinIsReverified(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		addr, pin, roots := sessionFixture(t, version)
		cache := fixedCache{utls.NewLRUClientSessionCache(1)}
		if _, err := sessionRoundTrip(addr, "localhost", pin, true, roots, cache); err != nil {
			t.Fatal(err)
		}
		if timings, err := sessionRoundTrip(addr, "localhost", strings.Repeat("00", 32), true, roots, cache); err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") || !timings.TLSResumed {
			t.Fatalf("cached pin bypass: %v", err)
		}
	}
}

func BenchmarkTLSHandshake(b *testing.B) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, enabled := range []bool{false, true} {
			name := tls.VersionName(version) + "/full"
			if enabled {
				name = tls.VersionName(version) + "/resumed"
			}
			b.Run(name, func(b *testing.B) {
				addr, pin, roots := sessionFixture(b, version)
				cache := utls.NewLRUClientSessionCache(64)
				if _, err := sessionRoundTrip(addr, "localhost", pin, enabled, roots, cache); err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					timings, err := sessionRoundTrip(addr, "localhost", pin, enabled, roots, cache)
					if err != nil || timings.TLSResumed != enabled {
						b.Fatalf("resumed=%v: %v", timings.TLSResumed, err)
					}
				}
			})
		}
	}
}
