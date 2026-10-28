package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestServerOutboundIPFamily(t *testing.T) {
	for _, tc := range []struct {
		name, field, family, tcp, udp string
		valid                         bool
	}{
		{"default", "", "auto", "tcp", "udp", true},
		{"empty", `,"outbound_ip_family":""`, "auto", "tcp", "udp", true},
		{"auto", `,"outbound_ip_family":"auto"`, "auto", "tcp", "udp", true},
		{"ipv4", `,"outbound_ip_family":"ipv4"`, "ipv4", "tcp4", "udp4", true},
		{"unknown", `,"outbound_ip_family":"ipv6"`, "", "", "", false},
		{"case", `,"outbound_ip_family":"IPv4"`, "", "", "", false},
		{"whitespace", `,"outbound_ip_family":" ipv4 "`, "", "", "", false},
		{"type", `,"outbound_ip_family":true`, "", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "server.json")
			if err := os.WriteFile(p, []byte(`{"auth_token":"placeholder","listen_addr":"[::]:8443","udp_quic_listen_addr":"[::]:8443"`+tc.field+`}`), 0600); err != nil {
				t.Fatal(err)
			}
			c, err := LoadServerConfig(p)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
			if !tc.valid {
				return
			}
			if c.OutboundIPFamily != tc.family || c.OutboundNetwork("tcp") != tc.tcp || c.OutboundNetwork("udp") != tc.udp {
				t.Fatalf("wrong outbound family: %+v", c)
			}
			if c.ListenAddr != "[::]:8443" || c.UDPQUICListenAddr != "[::]:8443" {
				t.Fatal("outbound selection changed listeners")
			}
		})
	}
}
