package config

import (
	"fmt"
	"time"

	"mygotunnel/internal/datagram"
	"mygotunnel/internal/tunnel"
)

// UDPQueueConfig is local policy and is never included in connection codes.
// Zero values select defaults; age bounds application queuing, not network RTT.
type UDPQueueConfig struct {
	UDPQueueMaxBytes    int `json:"udp_queue_max_bytes,omitempty"`
	UDPQueueMaxAgeMS    int `json:"udp_queue_max_age_ms,omitempty"`
	UDPWriteTimeoutMS   int `json:"udp_write_timeout_ms,omitempty"`
	UDPMaxSockets       int `json:"udp_max_sockets,omitempty"`
	UDPMemoryLimitBytes int `json:"udp_memory_limit_bytes,omitempty"`
}

func (c UDPQueueConfig) WriteTimeout() time.Duration {
	if c.UDPWriteTimeoutMS == 0 {
		return 5 * time.Second
	}
	return time.Duration(c.UDPWriteTimeoutMS) * time.Millisecond
}

func (c UDPQueueConfig) ProcessLimits() (int, int) {
	sockets, bytes := c.UDPMaxSockets, c.UDPMemoryLimitBytes
	if sockets == 0 {
		sockets = datagram.DefaultMaxSockets
	}
	if bytes == 0 {
		bytes = datagram.DefaultMemoryLimit
	}
	return sockets, bytes
}

func (c UDPQueueConfig) QueueLimits() (int, time.Duration) {
	bytes, age := c.UDPQueueMaxBytes, time.Duration(c.UDPQueueMaxAgeMS)*time.Millisecond
	if bytes == 0 {
		bytes = datagram.DefaultMaxBytes
	}
	if age == 0 {
		age = datagram.DefaultMaxAge
	}
	return bytes, age
}

func (c UDPQueueConfig) validate() error {
	if c.UDPWriteTimeoutMS < 0 || c.UDPWriteTimeoutMS > 600000 {
		return fmt.Errorf("udp_write_timeout_ms must be 0 (default) or 1..600000")
	}
	if c.UDPMaxSockets < 0 || c.UDPMaxSockets > 65536 {
		return fmt.Errorf("udp_max_sockets must be 0 (default) or 1..65536")
	}
	if c.UDPMemoryLimitBytes != 0 && (c.UDPMemoryLimitBytes < 262144 || c.UDPMemoryLimitBytes > 1073741824) {
		return fmt.Errorf("udp_memory_limit_bytes must be 0 (default) or 262144..1073741824")
	}
	if c.UDPQueueMaxBytes != 0 && (c.UDPQueueMaxBytes < tunnel.MaxDatagramSize || c.UDPQueueMaxBytes > 64*1024*1024) {
		return fmt.Errorf("udp_queue_max_bytes must be 0 (default) or %d..67108864", tunnel.MaxDatagramSize)
	}
	if c.UDPQueueMaxAgeMS < 0 || c.UDPQueueMaxAgeMS > 60000 {
		return fmt.Errorf("udp_queue_max_age_ms must be 0 (default) or 1..60000")
	}
	return nil
}
