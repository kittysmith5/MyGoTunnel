package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClientUDPRelayPolicyValidation(t *testing.T) {
	for _, tc := range []struct {
		fields string
		valid  bool
	}{
		{``, true}, {`,"udp_source_policy":"strict"`, true}, {`,"udp_source_policy":"nat","udp_relay_port_min":20000,"udp_relay_port_max":21023`, true},
		{`,"udp_source_policy":"any"`, false}, {`,"udp_relay_port_min":20000`, false},
		{`,"udp_relay_port_min":21000,"udp_relay_port_max":20000`, false},
		{`,"udp_relay_port_min":20000,"udp_relay_port_max":21024`, false},
		{`,"udp_relay_port_min":-1,"udp_relay_port_max":1`, false},
		{`,"udp_relay_port_min":65000,"udp_relay_port_max":65536`, false},
	} {
		path := filepath.Join(t.TempDir(), "client.json")
		if err := os.WriteFile(path, []byte(`{"remote_addr":"server.test:443","auth_token":"test"`+tc.fields+`}`), 0600); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadClientConfig(path)
		if (err == nil) != tc.valid {
			t.Fatalf("%s: %v", tc.fields, err)
		}
		if tc.fields == "" && cfg.UDPSourceMode() != "strict" {
			t.Fatal("default policy changed")
		}
	}
}
