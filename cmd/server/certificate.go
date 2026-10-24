package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"mygotunnel/internal/config"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

// Each published config is immutable, including its independent ticket keys.
// Existing connections retain their snapshot; new handshakes use the new pair.
type certificateManager struct {
	path     string
	baseline config.ServerConfig
	mu       sync.Mutex
	current  atomic.Pointer[tls.Config]
}

func newCertificateManager(path string, cfg *config.ServerConfig) (*certificateManager, error) {
	m := &certificateManager{path: path, baseline: *cfg}
	c, err := loadCertificateConfig(cfg)
	if err != nil {
		return nil, err
	}
	m.current.Store(c)
	return m, nil
}

func loadCertificateConfig(cfg *config.ServerConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate pair")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	now := time.Now()
	if err != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, fmt.Errorf("invalid certificate validity")
	}
	c := serverTLSConfig(cert)
	// GetConfigForClient otherwise inherits the listener's ticket keys. Bind
	// ticket encryption to this snapshot, retaining Go's automatic key rotation.
	c.WrapSession = c.EncryptTicket
	c.UnwrapSession = c.DecryptTicket
	return c, nil
}

func (m *certificateManager) tlsConfig() *tls.Config {
	c := serverTLSConfig(tls.Certificate{})
	c.Certificates = nil
	c.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return m.current.Load(), nil
	}
	return c
}

func (m *certificateManager) reload() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cfg, err := config.LoadServerConfig(m.path)
	if err != nil {
		return false, fmt.Errorf("invalid reload configuration")
	}
	protected := *cfg
	protected.CertFile, protected.KeyFile = m.baseline.CertFile, m.baseline.KeyFile
	if !reflect.DeepEqual(protected, m.baseline) {
		return false, fmt.Errorf("non-certificate settings changed")
	}
	next, err := loadCertificateConfig(cfg)
	if err != nil {
		return false, err
	}
	if reflect.DeepEqual(next.Certificates[0].Certificate, m.current.Load().Certificates[0].Certificate) {
		return false, nil
	}
	m.current.Store(next)
	return true, nil
}
