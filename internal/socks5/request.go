package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

func ReadRequest(conn net.Conn) (string, error) {
	header := make([]byte, 4)

	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}

	ver := header[0]
	cmd := header[1]
	atyp := header[3]

	if ver != 0x05 {
		return "", errors.New("invalid SOCKS version")
	}

	if cmd != 0x01 {
		return "", errors.New("only TCP CONNECT is supported")
	}

	var host string

	switch atyp {
	case 0x01:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()

	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", err
		}

		hostLen := int(lenBuf[0])
		hostBuf := make([]byte, hostLen)

		if _, err := io.ReadFull(conn, hostBuf); err != nil {
			return "", err
		}

		host = string(hostBuf)

	case 0x04:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()

	default:
		return "", errors.New("unsupported address type")
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}

	port := binary.BigEndian.Uint16(portBuf)

	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}
