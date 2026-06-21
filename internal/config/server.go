package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type ServerConfig struct {
	ListenAddr string `json:"listen_addr"`
	AuthToken  string `json:"auth_token"`
	CertFile   string `json:"cert_file"`
	KeyFile    string `json:"key_file"`
	QUICConfig
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

	if cfg.AuthToken == "" {
		return nil, fmt.Errorf("auth_token is empty")
	}

	if cfg.CertFile == "" {
		cfg.CertFile = "certs/cert.pem"
	}

	if cfg.KeyFile == "" {
		cfg.KeyFile = "certs/key.pem"
	}

	applyQUICDefaults(&cfg.QUICConfig)

	return &cfg, nil
}
