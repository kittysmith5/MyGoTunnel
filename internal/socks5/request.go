package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"unicode"
)

// RequestError carries the SOCKS5 reply appropriate for a rejected request.
type RequestError struct {
	Rep     byte
	message string
}

func (e *RequestError) Error() string { return e.message }
func requestError(rep byte, message string) error {
	return &RequestError{Rep: rep, message: message}
}

// ReplyCode maps malformed requests and transport failures to SOCKS5 responses.
func ReplyCode(err error) byte {
	var requestErr *RequestError
	if errors.As(err, &requestErr) {
		return requestErr.Rep
	}
	var coded interface{ SOCKSReplyCode() byte }
	if errors.As(err, &coded) {
		return coded.SOCKSReplyCode()
	}
	return 0x01
}

func ReadRequest(conn net.Conn) (string, error) {
	request, err := ReadRequestDetails(conn)
	if err != nil {
		return "", err
	}
	if request.Command != CommandConnect {
		return "", requestError(0x07, "only TCP CONNECT is supported")
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

	if header[2] != 0x00 {
		return Request{}, requestError(0x01, "invalid SOCKS5 reserved byte")
	}
	if cmd != CommandConnect && cmd != CommandUDPAssociate {
		return Request{}, requestError(0x07, "unsupported SOCKS command")
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
		if host == "" || strings.ContainsAny(host, ":/\\[]") {
			return Request{}, requestError(0x08, "invalid SOCKS5 domain")
		}
		for _, character := range host {
			if character < 0x20 || character == 0x7f || unicode.IsSpace(character) {
				return Request{}, requestError(0x08, "invalid SOCKS5 domain")
			}
		}

	case 0x04:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return Request{}, err
		}
		host = net.IP(addr).String()

	default:
		return Request{}, requestError(0x08, "unsupported address type")
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return Request{}, err
	}

	port := binary.BigEndian.Uint16(portBuf)
	if port == 0 && cmd == CommandConnect {
		return Request{}, requestError(0x01, "invalid SOCKS5 target port")
	}

	return Request{Command: cmd, Address: host, Port: port}, nil
}
