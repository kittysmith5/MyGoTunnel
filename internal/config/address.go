package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Listener validation is offline: port zero and an empty wildcard host keep
// their existing meaning. It does not resolve names or try to bind live ports.
func validateListenAddress(addr string) error {
	return validateEndpoint(addr, true, true)
}

func validateAddress(addr string) error {
	return validateEndpoint(addr, false, false)
}

func validateEndpoint(addr string, wildcard, zeroPort bool) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || (!wildcard && host == "") || port == "" {
		return fmt.Errorf("address must be host:port")
	}
	for _, digit := range port {
		if digit < '0' || digit > '9' {
			return fmt.Errorf("invalid address port")
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n > 65535 || (n == 0 && !zeroPort) {
		return fmt.Errorf("invalid address port")
	}
	if !utf8.ValidString(host) || strings.ContainsAny(host, "/\\[]") {
		return fmt.Errorf("invalid address host")
	}
	for _, character := range host {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return fmt.Errorf("invalid address host")
		}
	}
	// Colons and scopes belong to IP literals, never malformed DNS names.
	if strings.ContainsAny(host, ":%") {
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("invalid address host")
		}
	}
	return nil
}
