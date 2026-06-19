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

	_, err := conn.Write([]byte{0x05, 0x00})
	return err
}
