package socks5

import "net"

func ReplyBound(conn net.Conn, rep byte, addr *net.UDPAddr) error {
	if addr == nil {
		return Reply(conn, rep)
	}

	ip := addr.IP.To4()
	atyp := byte(0x01)
	if ip == nil {
		ip = addr.IP.To16()
		atyp = 0x04
	}
	if ip == nil {
		return Reply(conn, rep)
	}
	response := []byte{0x05, rep, 0x00, atyp}
	response = append(response, ip...)
	response = append(response, byte(addr.Port>>8), byte(addr.Port))
	_, err := conn.Write(response)
	return err
}

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
