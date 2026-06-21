package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type ClientConfig struct {
	LocalAddr                    string `json:"local_addr"`
	RemoteAddr                   string `json:"remote_addr"`
	AuthToken                    string `json:"auth_token"`
	SocksHandshakeTimeoutSeconds int    `json:"socks_handshake_timeout_seconds"`
	SocksRequestTimeoutSeconds   int    `json:"socks_request_timeout_seconds"`
	OpenStreamTimeoutSeconds     int    `json:"open_stream_timeout_seconds"`
	QUICConfig
}

type QUICConfig struct {
	KeepAlivePeriodSeconds         int    `json:"keep_alive_period_seconds"`
	MaxIdleTimeoutSeconds          int    `json:"max_idle_timeout_seconds"`
	HandshakeIdleTimeoutSeconds    int    `json:"handshake_idle_timeout_seconds"`
	InitialStreamReceiveWindow     uint64 `json:"initial_stream_receive_window"`
	MaxStreamReceiveWindow         uint64 `json:"max_stream_receive_window"`
	InitialConnectionReceiveWindow uint64 `json:"initial_connection_receive_window"`
	MaxConnectionReceiveWindow     uint64 `json:"max_connection_receive_window"`
	MaxIncomingStreams             int64  `json:"max_incoming_streams"`
	MaxIncomingUniStreams          int64  `json:"max_incoming_uni_streams"`
	InitialPacketSize              uint16 `json:"initial_packet_size"`
	DisablePathMTUDiscovery        bool   `json:"disable_path_mtu_discovery"`
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

	if cfg.SocksHandshakeTimeoutSeconds <= 0 {
		cfg.SocksHandshakeTimeoutSeconds = 10
	}

	if cfg.SocksRequestTimeoutSeconds <= 0 {
		cfg.SocksRequestTimeoutSeconds = 10
	}

	if cfg.OpenStreamTimeoutSeconds <= 0 {
		cfg.OpenStreamTimeoutSeconds = 10
	}

	applyQUICDefaults(&cfg.QUICConfig)

	return &cfg, nil
}
