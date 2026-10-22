package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type PreviousToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ServerConfig struct {
	UDPQueueConfig
	ListenAddr         string          `json:"listen_addr"`
	AuthToken          string          `json:"auth_token"`
	PreviousAuthTokens []PreviousToken `json:"previous_auth_tokens,omitempty"`
	CertFile           string          `json:"cert_file"`
	KeyFile            string          `json:"key_file"`
}

func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read server config failed: %w", err)
	}

	var cfg ServerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse server config failed: %w", err)
	}

	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":9001"
	}
	if err := validateListenAddress(cfg.ListenAddr); err != nil {
		return nil, fmt.Errorf("invalid listen_addr: %w", err)
	}

	if !validToken(cfg.AuthToken) {
		return nil, fmt.Errorf("auth_token is invalid")
	}
	if len(cfg.PreviousAuthTokens) > 1 {
		return nil, fmt.Errorf("at most one previous auth token is supported")
	}
	for _, p := range cfg.PreviousAuthTokens {
		if !validToken(p.Token) || p.Token == cfg.AuthToken || p.ExpiresAt.IsZero() {
			return nil, fmt.Errorf("invalid previous_auth_tokens entry")
		}
	}

	if cfg.CertFile == "" {
		cfg.CertFile = "certs/cert.pem"
	}

	if cfg.KeyFile == "" {
		cfg.KeyFile = "certs/key.pem"
	}
	if err := cfg.UDPQueueConfig.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func validToken(token string) bool {
	if token == "" || len(token) > 4089 || strings.TrimSpace(token) != token {
		return false
	}
	for _, r := range token {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
func (c *ServerConfig) ActiveAuthTokens(now time.Time) []string {
	out := []string{c.AuthToken}
	for _, p := range c.PreviousAuthTokens {
		if now.Before(p.ExpiresAt) {
			out = append(out, p.Token)
		}
	}
	return out
}
