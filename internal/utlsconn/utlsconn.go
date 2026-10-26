package utlsconn

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"mygotunnel/internal/dialmetrics"
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
	TCPDuration     time.Duration
	NodeDNSDuration time.Duration
	NodeTCPDuration time.Duration
	TLSDuration     time.Duration
	Stage           string
	TLSResumed      bool
}

type Options struct {
	SessionCache bool
}

func Dial(ctx context.Context, remoteAddr, sni, fingerprint string) (net.Conn, error) {
	conn, _, err := DialWithTimings(ctx, remoteAddr, sni, fingerprint)
	return conn, err
}

func DialWithTimings(ctx context.Context, remoteAddr, sni, fingerprint string) (net.Conn, DialTimings, error) {
	return DialWithOptions(ctx, remoteAddr, sni, fingerprint, Options{})
}

func DialWithOptions(ctx context.Context, remoteAddr, sni, fingerprint string, options Options) (net.Conn, DialTimings, error) {
	return dialWithOptions(ctx, remoteAddr, sni, fingerprint, options, nil, sessions)
}

func dialWithOptions(ctx context.Context, remoteAddr, sni, fingerprint string, options Options, roots *x509.CertPool, cache utls.ClientSessionCache) (net.Conn, DialTimings, error) {
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
	tcpConn, phases, err := dialmetrics.DialOnce(ctx, dialer, "tcp", remoteAddr)
	timings.NodeDNSDuration, timings.NodeTCPDuration = phases.DNS, phases.TCP
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
		MinVersion:         utls.VersionTLS12,
		RootCAs:            roots,
	}
	if options.SessionCache {
		scope := sha256.Sum256([]byte(remoteAddr + "\x00" + serverName + "\x00" + hex.EncodeToString(expected)))
		tlsConfig.ClientSessionCache = scopedCache{cache: cache, scope: hex.EncodeToString(scope[:])}
		tlsConfig.OmitEmptyPsk = true
	}
	if len(expected) != 0 {
		// The imported certificate pin replaces public CA verification.
		// VerifyConnection also runs on resumed connections.
		tlsConfig.VerifyConnection = func(state utls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("server certificate missing")
			}
			actual := sha256.Sum256(state.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(actual[:], expected) != 1 {
				return fmt.Errorf("server certificate fingerprint mismatch")
			}
			return nil
		}
	} else if options.SessionCache {
		tlsConfig.VerifyConnection = func(state utls.ConnectionState) error {
			if !state.DidResume {
				return nil // Normal CA verification already ran on full handshakes.
			}
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("server certificate missing")
			}
			intermediates := x509.NewCertPool()
			for _, c := range state.PeerCertificates[1:] {
				intermediates.AddCert(c)
			}
			_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: serverName, Roots: roots, Intermediates: intermediates})
			return err
		}
	}
	tlsConn := utls.UClient(tcpConn, tlsConfig, utls.HelloCustom)
	spec, err := tunnelHelloSpec()
	if err == nil && options.SessionCache {
		// Chrome_133's baseline has no PSK extension. It must be last and is
		// omitted on cold connections, rather than sending a fake empty PSK.
		spec.Extensions = append(spec.Extensions, &utls.UtlsPreSharedKeyExtension{})
	}
	if err == nil {
		err = tlsConn.ApplyPreset(spec)
	}
	if err != nil {
		_ = tcpConn.Close()
		return nil, timings, fmt.Errorf("prepare ClientHello: %w", err)
	}

	timings.Stage = "tls"
	tlsStarted := time.Now()
	err = tlsConn.HandshakeContext(ctx)
	timings.TLSDuration = time.Since(tlsStarted)
	timings.TLSResumed = tlsConn.ConnectionState().DidResume
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

// tunnelHelloSpec uses a reproducible Chrome baseline, adapted to our ALPN.
// Each connection needs its own spec: ApplyPreset mutates extension state.
func tunnelHelloSpec() (*utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
	if err != nil {
		return nil, err
	}
	extensions := spec.Extensions[:0]
	for _, extension := range spec.Extensions {
		switch e := extension.(type) {
		case *utls.ALPNExtension:
			e.AlpnProtocols = []string{"http/1.1"}
		case *utls.ApplicationSettingsExtension, *utls.ApplicationSettingsExtensionNew:
			continue // HTTP/2 application settings do not belong to this tunnel.
		}
		extensions = append(extensions, extension)
	}
	spec.Extensions = extensions
	return &spec, nil
}
