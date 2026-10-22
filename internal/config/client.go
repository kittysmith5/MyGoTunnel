package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type SOCKSAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type PreviousSOCKSAuth struct {
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ClientConfig struct {
	UDPQueueConfig
	SocksUsername          string              `json:"socks_username,omitempty"`
	SocksPassword          string              `json:"socks_password,omitempty"`
	SOCKSAuth              *SOCKSAuth          `json:"socks_auth,omitempty"`
	PreviousSOCKSAuth      []PreviousSOCKSAuth `json:"previous_socks_auth,omitempty"`
	LocalAddr              string              `json:"local_addr"`
	RemoteAddr             string              `json:"remote_addr"`
	AuthToken              string              `json:"auth_token"`
	SNI                    string              `json:"sni"`
	CertificateFingerprint string              `json:"certificate_fingerprint,omitempty"`
	UDPSourcePolicy        string              `json:"udp_source_policy,omitempty"`
	UDPRelayPortMin        int                 `json:"udp_relay_port_min,omitempty"`
	UDPRelayPortMax        int                 `json:"udp_relay_port_max,omitempty"`
}

func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client config failed: %w", err)
	}

	var cfg ClientConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse client config failed: %w", err)
	}

	if cfg.LocalAddr == "" {
		cfg.LocalAddr = "127.0.0.1:1080"
	}
	if err := validateListenAddress(cfg.LocalAddr); err != nil {
		return nil, fmt.Errorf("invalid local_addr: %w", err)
	}

	if cfg.RemoteAddr == "" {
		return nil, fmt.Errorf("remote_addr is empty")
	}

	if cfg.AuthToken == "" {
		return nil, fmt.Errorf("auth_token is empty")
	}

	if cfg.SOCKSAuth == nil && (cfg.SocksUsername != "" || cfg.SocksPassword != "") {
		cfg.SOCKSAuth = &SOCKSAuth{Username: cfg.SocksUsername, Password: cfg.SocksPassword}
	}
	if len(cfg.PreviousSOCKSAuth) > 1 {
		return nil, fmt.Errorf("at most one previous SOCKS credential is supported")
	}
	if len(cfg.PreviousSOCKSAuth) != 0 && cfg.SOCKSAuth == nil {
		return nil, fmt.Errorf("previous_socks_auth requires current SOCKS credentials")
	}
	if cfg.SOCKSAuth != nil {
		if len(cfg.SOCKSAuth.Username) < 1 || len(cfg.SOCKSAuth.Username) > 255 || len(cfg.SOCKSAuth.Password) < 1 || len(cfg.SOCKSAuth.Password) > 255 {
			return nil, fmt.Errorf("socks_auth username and password must each be 1..255 bytes")
		}
	}
	for _, a := range cfg.PreviousSOCKSAuth {
		if len(a.Username) < 1 || len(a.Username) > 255 || len(a.Password) < 1 || len(a.Password) > 255 || a.ExpiresAt.IsZero() {
			return nil, fmt.Errorf("invalid previous_socks_auth entry")
		}
	}
	if err := validateClient(&cfg); err != nil {
		return nil, err
	}
	if err := cfg.UDPQueueConfig.validate(); err != nil {
		return nil, err
	}
	if err := cfg.validateUDPRelay(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (cfg *ClientConfig) UDPSourceMode() string {
	if cfg.UDPSourcePolicy == "" {
		return "strict"
	}
	return cfg.UDPSourcePolicy
}

func (cfg *ClientConfig) validateUDPRelay() error {
	if mode := cfg.UDPSourceMode(); mode != "strict" && mode != "nat" {
		return fmt.Errorf("udp_source_policy must be strict or nat")
	}
	lo, hi := cfg.UDPRelayPortMin, cfg.UDPRelayPortMax
	if lo == 0 && hi == 0 {
		return nil
	}
	if lo < 1 || hi < lo || hi > 65535 || hi-lo >= 1024 {
		return fmt.Errorf("UDP relay port range must contain 1..1024 ports within 1..65535")
	}
	return nil
}

func (cfg *ClientConfig) SOCKSCredentials() (string, string, bool) {
	if cfg.SOCKSAuth != nil {
		return cfg.SOCKSAuth.Username, cfg.SOCKSAuth.Password, true
	}
	return cfg.SocksUsername, cfg.SocksPassword, cfg.SocksUsername != "" || cfg.SocksPassword != ""
}

func (cfg *ClientConfig) SOCKSCredentialSet(now time.Time) ([]SOCKSAuth, bool) {
	u, p, ok := cfg.SOCKSCredentials()
	if !ok {
		return nil, false
	}
	out := []SOCKSAuth{{Username: u, Password: p}}
	for _, a := range cfg.PreviousSOCKSAuth {
		if now.Before(a.ExpiresAt) {
			out = append(out, SOCKSAuth{Username: a.Username, Password: a.Password})
		}
	}
	return out, true
}
