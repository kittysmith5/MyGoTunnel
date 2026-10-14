package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type SOCKSAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ClientConfig struct {
	SOCKSAuth              *SOCKSAuth `json:"socks_auth,omitempty"`
	LocalAddr              string     `json:"local_addr"`
	RemoteAddr             string     `json:"remote_addr"`
	AuthToken              string     `json:"auth_token"`
	SNI                    string     `json:"sni"`
	CertificateFingerprint string     `json:"certificate_fingerprint,omitempty"`
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

	if cfg.RemoteAddr == "" {
		return nil, fmt.Errorf("remote_addr is empty")
	}

	if cfg.AuthToken == "" {
		return nil, fmt.Errorf("auth_token is empty")
	}

	if cfg.SOCKSAuth != nil {
		if len(cfg.SOCKSAuth.Username) < 1 || len(cfg.SOCKSAuth.Username) > 255 || len(cfg.SOCKSAuth.Password) < 1 || len(cfg.SOCKSAuth.Password) > 255 {
			return nil, fmt.Errorf("socks_auth username and password must each be 1..255 bytes")
		}
	}
	if err := validateClient(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
