package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

type UDPDatagram struct {
	Host string
	Port uint16
}

func ParseUDPDatagram(packet []byte) (UDPDatagram, []byte, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return UDPDatagram{}, nil, errors.New("invalid SOCKS5 UDP header or fragmented packet")
	}
	pos := 4
	var host string
	switch packet[3] {
	case 0x01:
		if len(packet) < pos+4+2 {
			return UDPDatagram{}, nil, io.ErrUnexpectedEOF
		}
		host = net.IP(packet[pos : pos+4]).String()
		pos += 4
	case 0x03:
		if len(packet) < pos+1 {
			return UDPDatagram{}, nil, io.ErrUnexpectedEOF
		}
		n := int(packet[pos])
		pos++
		if len(packet) < pos+n+2 {
			return UDPDatagram{}, nil, io.ErrUnexpectedEOF
		}
		host = string(packet[pos : pos+n])
		if err := validateDomain(host); err != nil {
			return UDPDatagram{}, nil, err
		}
		pos += n
	case 0x04:
		if len(packet) < pos+16+2 {
			return UDPDatagram{}, nil, io.ErrUnexpectedEOF
		}
		host = net.IP(packet[pos : pos+16]).String()
		pos += 16
	default:
		return UDPDatagram{}, nil, errors.New("unsupported SOCKS5 UDP address type")
	}
	port := binary.BigEndian.Uint16(packet[pos : pos+2])
	if port == 0 {
		return UDPDatagram{}, nil, requestError(0x01, "invalid SOCKS5 target port")
	}
	pos += 2
	return UDPDatagram{Host: host, Port: port}, packet[pos:], nil
}

func BuildUDPDatagram(destination UDPDatagram, payload []byte) []byte {
	packet := []byte{0, 0, 0}
	ip := net.ParseIP(destination.Host)
	if ip4 := ip.To4(); ip4 != nil {
		packet = append(packet, 0x01)
		packet = append(packet, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		packet = append(packet, 0x04)
		packet = append(packet, ip6...)
	} else {
		packet = append(packet, 0x03, byte(len(destination.Host)))
		packet = append(packet, destination.Host...)
	}
	packet = append(packet, byte(destination.Port>>8), byte(destination.Port))
	return append(packet, payload...)
}

const (
	CommandConnect      = 0x01
	CommandUDPAssociate = 0x03
)

type Request struct {
	Command byte
	Address string
	Port    uint16
}
