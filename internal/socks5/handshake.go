package socks5

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
)

func Handshake(conn net.Conn) error {
	return HandshakeWithCredentials(conn, "", "", false)
}

func HandshakeWithCredentials(conn net.Conn, username, password string, requireAuth bool) error {
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

	wantedMethod := byte(0x00)
	if requireAuth {
		if username == "" || password == "" || len(username) > 255 || len(password) > 255 {
			return errors.New("invalid SOCKS5 username or password configuration")
		}
		wantedMethod = 0x02
	}
	for _, method := range methods {
		if method == wantedMethod {
			if _, err := conn.Write([]byte{0x05, wantedMethod}); err != nil {
				return err
			}
			if requireAuth {
				return authenticateUserPassword(conn, username, password)
			}
			return nil
		}
	}

	_, err := conn.Write([]byte{0x05, 0xff})
	if err != nil {
		return err
	}
	return errors.New("no acceptable SOCKS5 authentication method")
}

func authenticateUserPassword(conn net.Conn, expectedUsername, expectedPassword string) error {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return fmt.Errorf("read SOCKS5 credentials: %w", err)
	}
	username := make([]byte, int(header[1]))
	if header[0] != 0x01 || len(username) == 0 {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return errors.New("invalid SOCKS5 username/password request")
	}
	if _, err := io.ReadFull(conn, username); err != nil {
		return fmt.Errorf("read SOCKS5 username: %w", err)
	}
	var passwordLength [1]byte
	if _, err := io.ReadFull(conn, passwordLength[:]); err != nil {
		return fmt.Errorf("read SOCKS5 password length: %w", err)
	}
	password := make([]byte, int(passwordLength[0]))
	if len(password) == 0 {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return errors.New("empty SOCKS5 password")
	}
	if _, err := io.ReadFull(conn, password); err != nil {
		return fmt.Errorf("read SOCKS5 password: %w", err)
	}
	validUsername := subtle.ConstantTimeCompare(username, []byte(expectedUsername))
	validPassword := subtle.ConstantTimeCompare(password, []byte(expectedPassword))
	if validUsername != 1 || validPassword != 1 {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return errors.New("SOCKS5 username or password rejected")
	}
	if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
		return fmt.Errorf("send SOCKS5 authentication response: %w", err)
	}
	return nil
}
