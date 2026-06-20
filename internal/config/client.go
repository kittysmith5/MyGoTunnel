package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type ClientConfig struct {
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	AuthToken  string `json:"auth_token"`
	SNI        string `json:"sni"`
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

	return &cfg, nil
}
