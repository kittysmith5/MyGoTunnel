package socks5

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"time"
)

type Credentials struct{ Username, Password string }

func Handshake(conn net.Conn) error { return HandshakeWithAuth(conn, nil) }

func HandshakeWithAuth(conn net.Conn, auth *Credentials) error {
	_, err := HandshakeWithAuthTimings(conn, auth)
	return err
}

// HandshakeTimings includes peer/network waiting as well as local processing.
// FirstByte ends at the first greeting byte; Method covers the rest of method
// negotiation and its reply; Auth covers RFC 1929, or is zero when disabled.
type HandshakeTimings struct {
	FirstByte, Method, Auth time.Duration
}

func HandshakeWithAuthTimings(conn net.Conn, auth *Credentials) (timings HandshakeTimings, err error) {
	if auth != nil && (len(auth.Username) < 1 || len(auth.Username) > 255 || len(auth.Password) < 1 || len(auth.Password) > 255) {
		return timings, errors.New("invalid SOCKS5 authentication configuration")
	}
	header := make([]byte, 2)
	started := time.Now()
	_, err = io.ReadFull(conn, header[:1])
	timings.FirstByte = time.Since(started)
	if err != nil {
		return timings, err
	}
	methodStarted := time.Now()
	defer func() {
		if timings.Method == 0 {
			timings.Method = time.Since(methodStarted)
		}
	}()
	if _, err := io.ReadFull(conn, header[1:]); err != nil {
		return timings, err
	}

	ver := header[0]
	nMethods := int(header[1])

	if ver != 0x05 {
		return timings, errors.New("not SOCKS5")
	}

	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return timings, err
	}

	wanted := byte(0)
	if auth != nil {
		wanted = 2
	}
	for _, method := range methods {
		if method == wanted {
			_, err := conn.Write([]byte{0x05, wanted})
			if err != nil {
				return timings, err
			}
			timings.Method = time.Since(methodStarted)
			if auth != nil {
				authStarted := time.Now()
				err := authenticate(conn, auth)
				timings.Auth = time.Since(authStarted)
				return timings, err
			}
			return timings, nil
		}
	}
	if _, err := conn.Write([]byte{0x05, 0xff}); err != nil {
		return timings, err
	}
	return timings, errors.New("no supported SOCKS5 authentication method")
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

func HandshakeWithCredentials(conn net.Conn, username, password string, requireAuth bool) error {
	if !requireAuth {
		return HandshakeWithAuth(conn, nil)
	}
	return HandshakeWithAuth(conn, &Credentials{Username: username, Password: password})
}
