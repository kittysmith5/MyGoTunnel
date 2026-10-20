package main

import (
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"syscall"

	"mygotunnel/internal/config"
)

// The default policy enforces the declared endpoint. NAT mode accepts only the
// TCP control peer IP, learns its mapped port from the first valid datagram,
// and never permits the source tuple to move during an association.
type udpSourceFilter struct {
	allowed []netip.Addr
	port    uint16
	bound   netip.AddrPort
}

func newUDPSourceFilter(ips []net.IP, port uint16) udpSourceFilter {
	f := udpSourceFilter{port: port}
	for _, ip := range ips {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			f.allowed = append(f.allowed, addr.Unmap())
		}
	}
	return f
}

func (f *udpSourceFilter) rejection(source netip.AddrPort) string {
	if f.bound.IsValid() {
		if source != f.bound {
			return "binding"
		}
		return ""
	}
	allowed := false
	for _, ip := range f.allowed {
		if source.Addr().Unmap().WithZone("") == ip {
			allowed = true
			break
		}
	}
	if !allowed {
		return "ip"
	}
	if f.port != 0 && source.Port() != f.port {
		return "port"
	}
	return ""
}

func listenUDPRelay(bindIP net.IP, cfg *config.ClientConfig) (*net.UDPConn, error) {
	if cfg.UDPRelayPortMin == 0 && cfg.UDPRelayPortMax == 0 {
		return net.ListenUDP("udp", &net.UDPAddr{IP: bindIP})
	}
	count := cfg.UDPRelayPortMax - cfg.UDPRelayPortMin + 1
	if cfg.UDPRelayPortMin < 1 || cfg.UDPRelayPortMax > 65535 || count < 1 || count > 1024 {
		return nil, errors.New("invalid UDP relay port range")
	}
	start := rand.IntN(count)
	var last error
	for i := 0; i < count; i++ {
		port := cfg.UDPRelayPortMin + (start+i)%count
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindIP, Port: port})
		if err == nil {
			return conn, nil
		}
		last = err
		if !errors.Is(err, syscall.EADDRINUSE) {
			return nil, err
		}
	}
	return nil, last
}
