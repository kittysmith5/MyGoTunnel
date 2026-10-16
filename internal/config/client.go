package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type ClientConfig struct {
	LocalAddr     string    `json:"local_addr"`
	RemoteAddr    string    `json:"remote_addr"`
	AuthToken     string    `json:"auth_token"`
	SNI           string    `json:"sni"`
	SocksAuth     SOCKSAuth `json:"socks_auth"`
	SocksUsername string    `json:"socks_username"`
	SocksPassword string    `json:"socks_password"`
}

type SOCKSAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (cfg *ClientConfig) SOCKSCredentials() (username, password string, enabled bool) {
	if cfg.SocksAuth.Username != "" || cfg.SocksAuth.Password != "" {
		return cfg.SocksAuth.Username, cfg.SocksAuth.Password, true
	}
	if cfg.SocksUsername != "" || cfg.SocksPassword != "" {
		return cfg.SocksUsername, cfg.SocksPassword, true
	}
	return "", "", false
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

	username, password, socksAuthEnabled := cfg.SOCKSCredentials()
	if socksAuthEnabled {
		if username == "" || password == "" {
			return nil, fmt.Errorf("SOCKS username and password must both be set when authentication is enabled")
		}
		if len(username) > 255 || len(password) > 255 {
			return nil, fmt.Errorf("SOCKS username and password must be at most 255 bytes")
		}
	}

	return &cfg, nil
}
