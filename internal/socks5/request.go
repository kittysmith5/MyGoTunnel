package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
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

func ReadRequest(conn net.Conn) (string, error) {
	request, err := ReadRequestDetails(conn)
	if err != nil {
		return "", err
	}
	if request.Command != CommandConnect {
		return "", errors.New("only TCP CONNECT is supported")
	}
	return net.JoinHostPort(request.Address, strconv.Itoa(int(request.Port))), nil
}

func ReadRequestDetails(conn net.Conn) (Request, error) {
	header := make([]byte, 4)

	if _, err := io.ReadFull(conn, header); err != nil {
		return Request{}, err
	}

	ver := header[0]
	cmd := header[1]
	atyp := header[3]

	if ver != 0x05 {
		return Request{}, errors.New("invalid SOCKS version")
	}

	if cmd != CommandConnect && cmd != CommandUDPAssociate {
		return Request{}, errors.New("unsupported SOCKS command")
	}

	var host string

	switch atyp {
	case 0x01:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return Request{}, err
		}
		host = net.IP(addr).String()

	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return Request{}, err
		}

		hostLen := int(lenBuf[0])
		hostBuf := make([]byte, hostLen)

		if _, err := io.ReadFull(conn, hostBuf); err != nil {
			return Request{}, err
		}

		host = string(hostBuf)

	case 0x04:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return Request{}, err
		}
		host = net.IP(addr).String()

	default:
		return Request{}, errors.New("unsupported address type")
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return Request{}, err
	}

	port := binary.BigEndian.Uint16(portBuf)

	return Request{Command: cmd, Address: host, Port: port}, nil
}
