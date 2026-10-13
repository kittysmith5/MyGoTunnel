package utlsconn

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

type closeWriter interface {
	CloseWrite() error
}

var _ closeWriter = (*utls.UConn)(nil)

// DialTimings separates TCP connection establishment (including DNS) from TLS.
type DialTimings struct {
	TCPDuration time.Duration
	TLSDuration time.Duration
	Stage       string
}

func Dial(ctx context.Context, remoteAddr, sni, fingerprint string) (net.Conn, error) {
	conn, _, err := DialWithTimings(ctx, remoteAddr, sni, fingerprint)
	return conn, err
}

func DialWithTimings(ctx context.Context, remoteAddr, sni, fingerprint string) (net.Conn, DialTimings, error) {
	timings := DialTimings{Stage: "config"}
	var expected []byte
	if fingerprint != "" {
		var err error
		expected, err = hex.DecodeString(fingerprint)
		if err != nil || len(expected) != sha256.Size {
			return nil, timings, fmt.Errorf("invalid certificate fingerprint")
		}
	}
	dialer := &net.Dialer{}
	timings.Stage = "tcp"
	tcpStarted := time.Now()
	tcpConn, err := dialer.DialContext(ctx, "tcp", remoteAddr)
	timings.TCPDuration = time.Since(tcpStarted)
	if err != nil {
		return nil, timings, err
	}

	serverName := sni
	if serverName == "" {
		serverName = serverNameFromAddr(remoteAddr)
	}

	tlsConfig := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: len(expected) != 0,
		NextProtos:         []string{"http/1.1"},
	}
	if len(expected) != 0 {
		// The imported certificate pin replaces public CA verification.
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("server certificate missing")
			}
			actual := sha256.Sum256(rawCerts[0])
			if subtle.ConstantTimeCompare(actual[:], expected) != 1 {
				return fmt.Errorf("server certificate fingerprint mismatch")
			}
			return nil
		}
	}
	tlsConn := utls.UClient(tcpConn, tlsConfig, utls.HelloChrome_Auto)

	timings.Stage = "tls"
	tlsStarted := time.Now()
	err = tlsConn.HandshakeContext(ctx)
	timings.TLSDuration = time.Since(tlsStarted)
	if err != nil {
		_ = tcpConn.Close()
		return nil, timings, err
	}

	timings.Stage = ""
	return tlsConn, timings, nil
}

func serverNameFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	return strings.Trim(host, "[]")
}
