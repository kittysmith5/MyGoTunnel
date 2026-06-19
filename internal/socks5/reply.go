package socks5

import "net"

func Reply(conn net.Conn, rep byte) error {
	_, err := conn.Write([]byte{
		0x05,
		rep,
		0x00,
		0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	})
	return err
}
