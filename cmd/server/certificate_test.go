package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"mygotunnel/internal/config"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestCertificateReloadRejectsInvalidValidity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")
	if _, err := config.InitializeServer(path, "localhost:8443", ":8443"); err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.LoadServerConfig(path)
	m, err := newCertificateManager(path, cfg)
	if err != nil {
		t.Fatal(err)
	}
	published := m.current.Load()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	next := *cfg
	next.CertFile = path + ".invalid.pem"
	next.KeyFile = path + ".invalid.key"
	os.WriteFile(next.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600)
	for _, period := range [][2]time.Duration{{-2 * time.Hour, -time.Hour}, {time.Hour, 2 * time.Hour}} {
		leaf := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(period[0]), NotAfter: time.Now().Add(period[1]), DNSNames: []string{"localhost"}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(next.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
		writeReloadConfig(t, path, &next)
		if _, err := m.reload(); err == nil || m.current.Load() != published {
			t.Fatal("invalid validity changed live certificate")
		}
	}
}

func writeReloadConfig(t *testing.T, path string, cfg *config.ServerConfig) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestCertificateReloadPreservesConnectionsAndInvalidatesOldTickets(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "server.json")
			if _, err := config.InitializeServer(path, "localhost:8443", ":8443"); err != nil {
				t.Fatal(err)
			}
			cfg, _ := config.LoadServerConfig(path)
			m, err := newCertificateManager(path, cfg)
			if err != nil {
				t.Fatal(err)
			}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					raw, err := ln.Accept()
					if err != nil {
						return
					}
					wg.Add(1)
					go func() {
						defer wg.Done()
						defer raw.Close()
						raw.SetDeadline(time.Now().Add(5 * time.Second))
						c := tls.Server(raw, m.tlsConfig())
						if c.Handshake() == nil {
							io.WriteString(c, "ok")
							io.Copy(c, c)
						}
					}()
				}
			}()
			defer func() { ln.Close(); <-done; wg.Wait() }()
			cache := tls.NewLRUClientSessionCache(8)
			dial := func() *tls.Conn {
				t.Helper()
				c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, ServerName: "localhost", MinVersion: version, MaxVersion: version, ClientSessionCache: cache})
				if err != nil {
					t.Fatal(err)
				}
				c.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
					c.Close()
					t.Fatal(err)
				}
				return c
			}
			old := dial()
			defer old.Close()
			oldLeaf := string(old.ConnectionState().PeerCertificates[0].Raw)
			resumed := dial()
			if !resumed.ConnectionState().DidResume {
				t.Fatal("ticket not resumed")
			}
			resumed.Close()
			initial := m.current.Load()
			if changed, err := m.reload(); err != nil || changed || initial != m.current.Load() {
				t.Fatalf("unchanged reload: %v", err)
			}
			otherPath := filepath.Join(t.TempDir(), "renewed.json")
			config.InitializeServer(otherPath, "localhost:8443", ":8443")
			renewed, _ := config.LoadServerConfig(otherPath)
			next := *cfg
			next.CertFile, next.KeyFile = renewed.CertFile, renewed.KeyFile
			writeReloadConfig(t, path, &next)
			if changed, err := m.reload(); err != nil || !changed {
				t.Fatalf("reload: %v", err)
			}
			fresh := dial()
			if fresh.ConnectionState().DidResume || string(fresh.ConnectionState().PeerCertificates[0].Raw) == oldLeaf {
				t.Fatal("old ticket identity survived certificate rotation")
			}
			fresh.Close()
			newResume := dial()
			if !newResume.ConnectionState().DidResume {
				t.Fatal("new certificate cannot resume")
			}
			newResume.Close()
			if _, err := old.Write([]byte("alive")); err != nil {
				t.Fatal(err)
			}
			data := make([]byte, 5)
			if _, err := io.ReadFull(old, data); err != nil || string(data) != "alive" {
				t.Fatalf("existing connection interrupted: %v", err)
			}
			published := m.current.Load()
			bad := next
			bad.KeyFile = cfg.KeyFile
			writeReloadConfig(t, path, &bad)
			if _, err := m.reload(); err == nil || m.current.Load() != published {
				t.Fatal("bad key changed live certificate")
			}
			bad = next
			bad.AuthToken = "unrelated-change"
			writeReloadConfig(t, path, &bad)
			if _, err := m.reload(); err == nil || m.current.Load() != published {
				t.Fatal("reload accepted non-certificate change")
			}
			os.WriteFile(path, []byte("{"), 0600)
			if _, err := m.reload(); err == nil || m.current.Load() != published {
				t.Fatal("malformed config changed live certificate")
			}
			writeReloadConfig(t, path, cfg)
			if changed, err := m.reload(); err != nil || !changed {
				t.Fatalf("rollback reload: %v", err)
			}
			rolledBack := dial()
			defer rolledBack.Close()
			if string(rolledBack.ConnectionState().PeerCertificates[0].Raw) != oldLeaf {
				t.Fatal("rollback failed")
			}
		})
	}
}
