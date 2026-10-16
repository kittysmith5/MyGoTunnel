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
	UDPQueueMaxBytes int `json:"udp_queue_max_bytes,omitempty"`
	UDPQueueMaxAgeMS int `json:"udp_queue_max_age_ms,omitempty"`
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
	if c.UDPQueueMaxBytes != 0 && (c.UDPQueueMaxBytes < tunnel.MaxDatagramSize || c.UDPQueueMaxBytes > 64*1024*1024) {
		return fmt.Errorf("udp_queue_max_bytes must be 0 (default) or %d..67108864", tunnel.MaxDatagramSize)
	}
	if c.UDPQueueMaxAgeMS < 0 || c.UDPQueueMaxAgeMS > 60000 {
		return fmt.Errorf("udp_queue_max_age_ms must be 0 (default) or 1..60000")
	}
	return nil
}
