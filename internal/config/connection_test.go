package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitializeExportImport(t *testing.T) {
	dir := t.TempDir()
	serverPath := filepath.Join(dir, "server.json")
	code, err := InitializeServer(serverPath, "[::1]:9001", ":9001")
	if err != nil {
		t.Fatal(err)
	}
	server, err := LoadServerConfig(serverPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(server.CertFile, server.KeyFile); err != nil {
		t.Fatal(err)
	}
	exported, err := ExportServer(serverPath, "[::1]:9001")
	if err != nil || exported != code {
		t.Fatalf("export mismatch: %v", err)
	}
	clientPath := filepath.Join(dir, "client.json")
	if err := ImportClient(strings.NewReader(code+"\n"), clientPath); err != nil {
		t.Fatal(err)
	}
	client, err := LoadClientConfig(clientPath)
	if err != nil {
		t.Fatal(err)
	}
	if client.AuthToken != server.AuthToken || client.RemoteAddr != "[::1]:9001" || client.SNI != "::1" || client.LocalAddr != "127.0.0.1:1080" || len(client.CertificateFingerprint) != 64 {
		t.Fatal("imported config mismatch")
	}
	for _, path := range []string{serverPath, server.CertFile, server.KeyFile, clientPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0077 != 0 {
			t.Fatalf("credentials readable by other users: %s", path)
		}
	}
	before, _ := os.ReadFile(clientPath)
	if err := ImportClient(strings.NewReader(code), clientPath); err == nil {
		t.Fatal("import overwrote existing config")
	}
	after, _ := os.ReadFile(clientPath)
	if string(before) != string(after) {
		t.Fatal("import changed config")
	}
	if _, err := InitializeServer(serverPath, "[::1]:9001", ":9001"); err == nil {
		t.Fatal("initialization overwrote existing credentials")
	}
	if exportedAgain, err := ExportServer(serverPath, "[::1]:9001"); err != nil || exportedAgain != code {
		t.Fatal("existing credentials changed")
	}
}

func TestInitializeRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")
	if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InitializeServer(path, "example.test:9001", ":9001"); err == nil {
		t.Fatal("expected existing file error")
	}
	for _, suffix := range []string{".cert.pem", ".key.pem"} {
		if _, err := os.Stat(path + suffix); !os.IsNotExist(err) {
			t.Fatal("partial credentials were left behind")
		}
	}
	data, _ := os.ReadFile(path)
	if string(data) != "existing" {
		t.Fatal("existing file changed")
	}
}

func TestConnectionValidation(t *testing.T) {
	cfg := &ClientConfig{RemoteAddr: "example.test:9001", AuthToken: "test-token", CertificateFingerprint: strings.Repeat("ab", 32)}
	code, err := EncodeConnection(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeConnection(" " + code + "\r\n"); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*ClientConfig){
		func(c *ClientConfig) { c.RemoteAddr = "host:0" },
		func(c *ClientConfig) { c.RemoteAddr = ":9001" },
		func(c *ClientConfig) { c.AuthToken = "secret\nAUTH x" },
		func(c *ClientConfig) { c.AuthToken = "" },
		func(c *ClientConfig) { c.CertificateFingerprint = ""; c.TrustMode = "pin" },
		func(c *ClientConfig) { c.CertificateFingerprint = "bad" },
		func(c *ClientConfig) { c.SNI = "bad\nhost" },
	} {
		c := *cfg
		change(&c)
		if _, err := EncodeConnection(&c); err == nil {
			t.Fatal("accepted invalid config")
		}
	}
	for _, invalid := range []string{"", "https://example.test", codePrefix + "!", strings.Repeat("x", maxCodeBytes+1)} {
		if _, err := DecodeConnection(invalid); err == nil {
			t.Fatal("accepted invalid code")
		}
	}
	for _, version := range []int{0, 3} {
		data, _ := json.Marshal(connectionCode{Version: version, RemoteAddr: cfg.RemoteAddr, AuthToken: cfg.AuthToken, Fingerprint: cfg.CertificateFingerprint})
		if _, err := DecodeConnection(codePrefix + base64.RawURLEncoding.EncodeToString(data)); err == nil {
			t.Fatal("accepted unsupported version")
		}
	}
	path := filepath.Join(t.TempDir(), "client.json")
	if err := ImportClient(strings.NewReader(strings.Repeat("x", maxCodeBytes+100)), path); err == nil {
		t.Fatal("accepted oversized input")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("invalid import wrote a file")
	}
}

func TestConnectionCATrustAndLegacyBoundary(t *testing.T) {
	cfg := &ClientConfig{RemoteAddr: "localhost:8443", AuthToken: "test-only", SNI: "localhost", TrustMode: "ca", TLSSessionCache: true, SOCKSAuth: &SOCKSAuth{Username: "local-only", Password: "local-only"}}
	code, err := EncodeConnection(cfg)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeConnection(code)
	if err != nil || decoded.TrustMode != "ca" || decoded.CertificateFingerprint != "" || decoded.TLSSessionCache || decoded.SOCKSAuth != nil {
		t.Fatalf("CA import or local policy isolation: %v", err)
	}
	path := filepath.Join(t.TempDir(), "client.json")
	if err := ImportClient(strings.NewReader(code), path); err != nil {
		t.Fatal(err)
	}
	if loaded, err := LoadClientConfig(path); err != nil || loaded.EffectiveTrustMode() != "ca" {
		t.Fatalf("CA load: %v", err)
	}
	for _, tc := range []connectionCode{
		{Version: 1, RemoteAddr: cfg.RemoteAddr, AuthToken: cfg.AuthToken},
		{Version: 1, RemoteAddr: cfg.RemoteAddr, AuthToken: cfg.AuthToken, TrustMode: "ca"},
		{Version: 2, RemoteAddr: cfg.RemoteAddr, AuthToken: cfg.AuthToken},
		{Version: 2, RemoteAddr: cfg.RemoteAddr, AuthToken: cfg.AuthToken, TrustMode: "ca", Fingerprint: strings.Repeat("ab", 32)},
		{Version: 2, RemoteAddr: cfg.RemoteAddr, AuthToken: cfg.AuthToken, TrustMode: "pin"},
	} {
		data, _ := json.Marshal(tc)
		if _, err := DecodeConnection(codePrefix + base64.RawURLEncoding.EncodeToString(data)); err == nil {
			t.Fatal("accepted ambiguous trust")
		}
	}
	for _, tc := range []ClientConfig{
		{RemoteAddr: cfg.RemoteAddr, AuthToken: cfg.AuthToken, TrustMode: "skip"},
		{RemoteAddr: cfg.RemoteAddr, AuthToken: cfg.AuthToken, TrustMode: "pin"},
		{RemoteAddr: cfg.RemoteAddr, AuthToken: cfg.AuthToken, TrustMode: "ca", CertificateFingerprint: strings.Repeat("ab", 32)},
	} {
		data, _ := json.Marshal(tc)
		os.WriteFile(path, data, 0600)
		if _, err := LoadClientConfig(path); err == nil {
			t.Fatal("accepted invalid config trust mode")
		}
	}
}

func TestCAExportValidatesChainAndHostname(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")
	if _, err := InitializeServer(path, "localhost:8443", ":8443"); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportServerWithTrust(path, "localhost:8443", "ca"); err == nil {
		t.Fatal("self-signed cert exported as public CA")
	}
	cfg, _ := LoadServerConfig(path)
	pair, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	code, err := exportServerWithTrust(path, "localhost:8443", "ca", roots)
	if err != nil {
		t.Fatal(err)
	}
	client, err := DecodeConnection(code)
	if err != nil || client.TrustMode != "ca" || client.SNI != "localhost" || client.CertificateFingerprint != "" {
		t.Fatalf("CA export: %v", err)
	}
	if _, err := exportServerWithTrust(path, "wrong.example:8443", "ca", roots); err == nil {
		t.Fatal("wrong hostname accepted")
	}
	if _, err := ExportServerWithTrust(path, "localhost:8443", "unknown"); err == nil {
		t.Fatal("unknown mode accepted")
	}
}

func TestLoadClientConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.json")
	if _, err := LoadClientConfig(path); err == nil {
		t.Fatal("missing config accepted")
	}
	for _, value := range []string{`{`, `{}`, `{"remote_addr":"host:9001"}`, `{"remote_addr":"host:9001","auth_token":"test","certificate_fingerprint":"bad"}`} {
		os.WriteFile(path, []byte(value), 0600)
		if _, err := LoadClientConfig(path); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
	os.WriteFile(path, []byte(`{"remote_addr":"host:9001","auth_token":"test"}`), 0600)
	cfg, err := LoadClientConfig(path)
	if err != nil || cfg.LocalAddr != "127.0.0.1:1080" {
		t.Fatalf("legacy config defaults: %v", err)
	}
}
