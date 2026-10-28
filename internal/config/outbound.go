package config

// OutboundNetwork selects the target socket family without changing tunnel
// listeners, client transports, system routing or the standard DNS resolver.
// Only the base TCP/UDP networks used by target dialers are passed here.
func (c *ServerConfig) OutboundNetwork(network string) string {
	if c.OutboundIPFamily == "ipv4" {
		switch network {
		case "tcp":
			return "tcp4"
		case "udp":
			return "udp4"
		}
	}
	return network
}
