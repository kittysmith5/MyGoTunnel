package socks5

import (
	"errors"
	"io"
	"net"
)

func Handshake(conn net.Conn) error {
	header := make([]byte, 2)

	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	ver := header[0]
	nMethods := int(header[1])

	if ver != 0x05 {
		return errors.New("not SOCKS5")
	}

	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	for _, method := range methods {
		if method == 0x00 {
			_, err := conn.Write([]byte{0x05, 0x00})
			return err
		}
	}
	if _, err := conn.Write([]byte{0x05, 0xff}); err != nil {
		return err
	}
	return errors.New("no supported SOCKS5 authentication method")
}
