package config

import "fmt"

// UDPTransportMode keeps legacy configurations on the TLS/TCP transport.
func (cfg *ClientConfig) UDPTransportMode() string {
	if cfg.UDPTransport == "" {
		return "tcp"
	}
	return cfg.UDPTransport
}

// UDPQUICRemote uses an explicit UDP endpoint when configured. Otherwise QUIC
// uses the existing remote host and numeric port, over UDP instead of TCP.
func (cfg *ClientConfig) UDPQUICRemote() string {
	if cfg.UDPQUICRemoteAddr != "" {
		return cfg.UDPQUICRemoteAddr
	}
	return cfg.RemoteAddr
}

func (cfg *ClientConfig) validateUDPTransport() error {
	if mode := cfg.UDPTransportMode(); mode != "tcp" && mode != "quic" {
		return fmt.Errorf("udp_transport must be tcp or quic")
	}
	if cfg.UDPQUICRemoteAddr != "" {
		if err := validateAddress(cfg.UDPQUICRemoteAddr); err != nil {
			return fmt.Errorf("invalid udp_quic_remote_addr: %w", err)
		}
	}
	return nil
}
