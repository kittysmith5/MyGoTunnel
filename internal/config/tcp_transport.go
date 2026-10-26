package config

import "fmt"

func (c *ClientConfig) TCPTransportMode() string {
	if c.TCPTransport == "" {
		return "tcp"
	}
	return c.TCPTransport
}
func (c *ClientConfig) TCPQUICRemote() string {
	if c.TCPQUICRemoteAddr != "" {
		return c.TCPQUICRemoteAddr
	}
	return c.RemoteAddr
}
func (c *ClientConfig) validateTCPTransport() error {
	if m := c.TCPTransportMode(); m != "tcp" && m != "quic" {
		return fmt.Errorf("tcp_transport must be tcp or quic")
	}
	if c.TCPQUICRemoteAddr != "" {
		if e := validateAddress(c.TCPQUICRemoteAddr); e != nil {
			return fmt.Errorf("invalid tcp_quic_remote_addr: %w", e)
		}
	}
	return nil
}
