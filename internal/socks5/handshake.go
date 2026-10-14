package socks5

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"net"
)

type Credentials struct{ Username, Password string }

func Handshake(conn net.Conn) error { return HandshakeWithAuth(conn, nil) }

func HandshakeWithAuth(conn net.Conn, auth *Credentials) error {
	if auth != nil && (len(auth.Username) < 1 || len(auth.Username) > 255 || len(auth.Password) < 1 || len(auth.Password) > 255) {
		return errors.New("invalid SOCKS5 authentication configuration")
	}
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

	wanted := byte(0)
	if auth != nil {
		wanted = 2
	}
	for _, method := range methods {
		if method == wanted {
			_, err := conn.Write([]byte{0x05, wanted})
			if err != nil {
				return err
			}
			if auth != nil {
				return authenticate(conn, auth)
			}
			return nil
		}
	}
	if _, err := conn.Write([]byte{0x05, 0xff}); err != nil {
		return err
	}
	return errors.New("no supported SOCKS5 authentication method")
}

// RFC 1929 authentication is bounded by the caller's SOCKS setup deadline.
func authenticate(conn net.Conn, auth *Credentials) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	reject := func() error {
		if _, err := conn.Write([]byte{1, 1}); err != nil {
			return err
		}
		return errors.New("SOCKS5 authentication rejected")
	}
	if header[0] != 1 || header[1] == 0 {
		return reject()
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, header[:1]); err != nil {
		return err
	}
	if header[0] == 0 {
		return reject()
	}
	password := make([]byte, int(header[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}
	// Fixed-size digests avoid length-dependent credential comparisons.
	actualUser, expectedUser := sha256.Sum256(username), sha256.Sum256([]byte(auth.Username))
	actualPass, expectedPass := sha256.Sum256(password), sha256.Sum256([]byte(auth.Password))
	if subtle.ConstantTimeCompare(actualUser[:], expectedUser[:])&subtle.ConstantTimeCompare(actualPass[:], expectedPass[:]) != 1 {
		return reject()
	}
	_, err := conn.Write([]byte{1, 0})
	return err
}
