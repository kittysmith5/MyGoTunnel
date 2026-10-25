package quicudp

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
)

// ALPN identifies this protocol; it does not advertise HTTP/3 or a browser.
const ALPN = "mygotunnel-udp/1"

// ALPNCompact adds complete, unfragmented packets when the discovered path MTU
// permits them. Version 1 fragments remain valid on this protocol.
const ALPNCompact = "mygotunnel-udp/2"

func Protocols() []string { return []string{ALPNCompact, ALPN} }

// ClientTLSConfig retains the existing CA-or-pin trust policy. QUIC uses the
// standard TLS 1.3 implementation, with no session cache or application 0-RTT.
func ClientTLSConfig(remoteAddr, sni, fingerprint string) (*tls.Config, error) {
	if sni == "" {
		var err error
		sni, _, err = net.SplitHostPort(remoteAddr)
		if err != nil || sni == "" {
			return nil, fmt.Errorf("invalid QUIC server address")
		}
	}
	c := &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS13, NextProtos: Protocols()}
	if fingerprint == "" {
		return c, nil
	}
	expected, err := hex.DecodeString(fingerprint)
	if err != nil || len(expected) != sha256.Size {
		return nil, fmt.Errorf("invalid certificate fingerprint")
	}
	c.InsecureSkipVerify = true // The explicit leaf pin replaces CA validation.
	c.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return fmt.Errorf("server certificate missing")
		}
		actual := sha256.Sum256(state.PeerCertificates[0].Raw)
		if subtle.ConstantTimeCompare(actual[:], expected) != 1 {
			return fmt.Errorf("server certificate fingerprint mismatch")
		}
		return nil
	}
	return c, nil
}
