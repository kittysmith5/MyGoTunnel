package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTCPTransportConfig(t *testing.T) {
	for _, tc := range []struct {
		name, fields string
		ok           bool
	}{
		{"default", "", true}, {"quic", `,"tcp_transport":"quic","tcp_quic_remote_addr":"node.example:18445"`, true},
		{"unknown", `,"tcp_transport":"auto"`, false}, {"bad remote", `,"tcp_quic_remote_addr":"node.example:0"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "client.json")
			os.WriteFile(p, []byte(`{"remote_addr":"node.example:443","auth_token":"placeholder"`+tc.fields+`}`), 0600)
			c, e := LoadClientConfig(p)
			if (e == nil) != tc.ok {
				t.Fatal(e)
			}
			if e == nil && tc.name == "default" && c.TCPTransportMode() != "tcp" {
				t.Fatal("default changed")
			}
		})
	}
	p := filepath.Join(t.TempDir(), "server.json")
	os.WriteFile(p, []byte(`{"auth_token":"placeholder","tcp_quic_listen_addr":":18445","udp_quic_listen_addr":":18445"}`), 0600)
	if _, e := LoadServerConfig(p); e == nil {
		t.Fatal("conflicting UDP sockets accepted")
	}
}
