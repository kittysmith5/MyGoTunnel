package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"unicode"
)

// Literal addresses use their SOCKS address type. In particular an IPv6 literal
// must not be sent as a domain, where ':' is correctly rejected by the proxy.
func buildConnectRequest(target string) ([]byte, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	p, err := net.LookupPort("tcp", port)
	if err != nil || p < 1 || p > 65535 {
		return nil, fmt.Errorf("invalid target port")
	}
	request := []byte{5, 1, 0}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return nil, fmt.Errorf("SOCKS target cannot encode an IPv6 zone")
		}
		ip = ip.Unmap()
		if ip.Is4() {
			request = append(request, 1)
		} else {
			request = append(request, 4)
		}
		request = append(request, ip.AsSlice()...)
	} else {
		if len(host) == 0 || len(host) > 255 || strings.ContainsAny(host, ":/\\[]") {
			return nil, fmt.Errorf("invalid target host")
		}
		for _, c := range host {
			if unicode.IsSpace(c) || unicode.IsControl(c) {
				return nil, fmt.Errorf("invalid target host")
			}
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	}
	return binary.BigEndian.AppendUint16(request, uint16(p)), nil
}
