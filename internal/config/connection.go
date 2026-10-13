package config

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const codePrefix = "mygotunnel://"
const maxCodeBytes = 8192

type connectionCode struct {
	Version     int    `json:"version"`
	RemoteAddr  string `json:"remote_addr"`
	AuthToken   string `json:"auth_token"`
	SNI         string `json:"sni,omitempty"`
	Fingerprint string `json:"certificate_fingerprint"`
}

func validateAddress(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return fmt.Errorf("address must be host:port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid address port")
	}
	if strings.ContainsAny(host, "/\\[]") {
		return fmt.Errorf("invalid address host")
	}
	for _, c := range host {
		if unicode.IsSpace(c) || unicode.IsControl(c) {
			return fmt.Errorf("invalid address host")
		}
	}
	return nil
}

func validateClient(cfg *ClientConfig) error {
	if err := validateAddress(cfg.RemoteAddr); err != nil {
		return err
	}
	if len(cfg.AuthToken) == 0 || len(cfg.AuthToken) > 4089 || strings.TrimSpace(cfg.AuthToken) != cfg.AuthToken {
		return fmt.Errorf("invalid auth_token")
	}
	for _, c := range cfg.AuthToken {
		if unicode.IsControl(c) {
			return fmt.Errorf("invalid auth_token")
		}
	}
	if cfg.CertificateFingerprint != "" {
		pin, err := hex.DecodeString(cfg.CertificateFingerprint)
		if err != nil || len(pin) != sha256.Size {
			return fmt.Errorf("invalid certificate_fingerprint")
		}
	}
	for _, c := range cfg.SNI {
		if unicode.IsSpace(c) || unicode.IsControl(c) {
			return fmt.Errorf("invalid sni")
		}
	}
	return nil
}

func EncodeConnection(cfg *ClientConfig) (string, error) {
	if err := validateClient(cfg); err != nil {
		return "", err
	}
	if cfg.CertificateFingerprint == "" {
		return "", fmt.Errorf("certificate_fingerprint required for connection code")
	}
	data, err := json.Marshal(connectionCode{1, cfg.RemoteAddr, cfg.AuthToken, cfg.SNI, cfg.CertificateFingerprint})
	if err != nil {
		return "", fmt.Errorf("encode connection code failed")
	}
	code := codePrefix + base64.RawURLEncoding.EncodeToString(data)
	if len(code) > maxCodeBytes {
		return "", fmt.Errorf("connection code too long")
	}
	return code, nil
}

func DecodeConnection(code string) (*ClientConfig, error) {
	code = strings.TrimSpace(code)
	if len(code) > maxCodeBytes || !strings.HasPrefix(code, codePrefix) {
		return nil, fmt.Errorf("invalid connection code")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, codePrefix))
	if err != nil {
		return nil, fmt.Errorf("invalid connection code encoding")
	}
	var value connectionCode
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, fmt.Errorf("invalid connection code data")
	}
	if value.Version != 1 {
		return nil, fmt.Errorf("unsupported connection code version")
	}
	cfg := &ClientConfig{LocalAddr: "127.0.0.1:1080", RemoteAddr: value.RemoteAddr, AuthToken: value.AuthToken, SNI: value.SNI, CertificateFingerprint: value.Fingerprint}
	if cfg.CertificateFingerprint == "" {
		return nil, fmt.Errorf("connection code missing certificate fingerprint")
	}
	if err := validateClient(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// writePrivate creates a new file exclusively; never overwrite existing credentials.
func writePrivate(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create credential file: %w", err)
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return fmt.Errorf("write credential file failed")
	}
	return nil
}

func ImportClient(input io.Reader, path string) error {
	reader := bufio.NewReader(io.LimitReader(input, maxCodeBytes+2))
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("read connection code failed")
	}
	if len(line) > maxCodeBytes+1 {
		return fmt.Errorf("connection code too long")
	}
	cfg, err := DecodeConnection(line)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode client config failed")
	}
	return writePrivate(path, append(data, '\n'))
}

func ExportServer(path, publicAddr string) (string, error) {
	if err := validateAddress(publicAddr); err != nil {
		return "", err
	}
	cfg, err := LoadServerConfig(path)
	if err != nil {
		return "", err
	}
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return "", fmt.Errorf("load server certificate: %w", err)
	}
	fingerprint := sha256.Sum256(cert.Certificate[0])
	host, _, _ := net.SplitHostPort(publicAddr)
	return EncodeConnection(&ClientConfig{RemoteAddr: publicAddr, AuthToken: cfg.AuthToken, SNI: host, CertificateFingerprint: hex.EncodeToString(fingerprint[:])})
}

func InitializeServer(path, publicAddr, listenAddr string) (string, error) {
	if err := validateAddress(publicAddr); err != nil {
		return "", err
	}
	// Empty listen host is allowed; the public endpoint must always be explicit.
	_, port, err := net.SplitHostPort(listenAddr)
	n, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid listen address")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate private key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", fmt.Errorf("generate certificate serial: %w", err)
	}
	host, _, _ := net.SplitHostPort(publicAddr)
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(5, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", fmt.Errorf("generate certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("encode private key: %w", err)
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	cfg := &ServerConfig{ListenAddr: listenAddr, AuthToken: base64.RawURLEncoding.EncodeToString(token), CertFile: absolute + ".cert.pem", KeyFile: absolute + ".key.pem"}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode server config failed")
	}
	fingerprint := sha256.Sum256(der)
	code, err := EncodeConnection(&ClientConfig{RemoteAddr: publicAddr, AuthToken: cfg.AuthToken, SNI: host, CertificateFingerprint: hex.EncodeToString(fingerprint[:])})
	if err != nil {
		return "", err
	}
	files := []struct {
		path string
		data []byte
	}{
		{cfg.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})},
		{cfg.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})},
		{absolute, append(data, '\n')},
	}
	var created []string
	for _, file := range files {
		if err := writePrivate(file.path, file.data); err != nil {
			for _, name := range created {
				_ = os.Remove(name)
			}
			return "", err
		}
		created = append(created, file.path)
	}
	return code, nil
}
