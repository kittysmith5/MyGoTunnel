package operations

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/quicudp"
	"mygotunnel/internal/tunnel"
)

func healthTestCertificate(t *testing.T) (*config.ServerConfig, tls.Certificate, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.json")
	code, err := config.InitializeServer(path, "health.test:8443", "127.0.0.1:8443")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadServerConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	client, err := config.DecodeConnection(code)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, cert, client.CertificateFingerprint
}

// healthTestListener implements only the authenticated control protocol. It
// neither enables DATAGRAM forwarding nor opens any target sockets.
func healthTestListener(t *testing.T, kind string, cert tls.Certificate, token string, stall bool) net.Listener {
	t.Helper()
	var listener net.Listener
	var err error
	var resources *datagram.Resources
	if kind == "quic" {
		resources = datagram.NewResources(16, 1<<20)
		listener, err = quicudp.Listen("127.0.0.1:0", &tls.Config{
			Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{quicudp.ALPN},
		}, resources, datagram.DefaultMaxAge, 8)
	} else {
		listener, err = tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{
			Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"},
		})
	}
	if err != nil {
		if resources != nil {
			resources.Close()
		}
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func(conn net.Conn) {
				defer workers.Done()
				defer conn.Close()
				if q, ok := conn.(*quicudp.Conn); ok {
					defer func() {
						if q.PreAuthDrops() != 0 {
							t.Error("health probe sent business datagrams")
						}
					}()
				}
				if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					return
				}
				reader := bufio.NewReader(conn)
				auth, err := tunnel.ReadLine(reader)
				if err != nil {
					return
				}
				if auth != "AUTH "+token {
					_, _ = io.WriteString(conn, "ERR\n")
					return
				}
				command, err := tunnel.ReadLine(reader)
				if err != nil {
					return
				}
				if !stall {
					switch command {
					case "PREPARE":
						_, err = io.WriteString(conn, "OK\nREADY\n")
					case "UDP":
						_, err = io.WriteString(conn, "OK\nOK\n")
					default:
						return
					}
					if err != nil {
						return
					}
				}
				_, _ = io.Copy(io.Discard, reader)
			}(conn)
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		workers.Wait()
		if resources != nil {
			resources.Close()
		}
	})
	return listener
}

func TestProbeQUICControlTrustAuthAndCancellation(t *testing.T) {
	cfg, cert, pin := healthTestCertificate(t)
	listener := healthTestListener(t, "quic", cert, cfg.AuthToken, false)
	for _, tc := range []struct {
		name, token, pin string
		good             bool
	}{
		{"success", cfg.AuthToken, pin, true},
		{"wrong token", "WRONG_HEALTH_TOKEN", pin, false},
		{"wrong pin", cfg.AuthToken, strings.Repeat("00", 32), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := probeQUICControl(ctx, listener.Addr().String(), "health.test", tc.pin, tc.token)
			if (err == nil) != tc.good {
				t.Fatalf("expected success=%v: %v", tc.good, err)
			}
		})
	}
	t.Run("stalled control cancellation", func(t *testing.T) {
		listener := healthTestListener(t, "quic", cert, cfg.AuthToken, true)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		started := time.Now()
		err := probeQUICControl(ctx, listener.Addr().String(), "health.test", pin, cfg.AuthToken)
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
			t.Fatalf("unbounded control probe: %v", err)
		}
	})
}

func TestProbeQUICControlUnreachableUDPIsBounded(t *testing.T) {
	// Reserve a local UDP socket without a QUIC responder, avoiding races with
	// another test binding a port that was briefly released.
	blackhole, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = probeQUICControl(ctx, blackhole.LocalAddr().String(), "health.test", strings.Repeat("00", 32), "HEALTH_TOKEN")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatalf("unbounded unreachable probe: %v", err)
	}
}

func TestLocalListenerAddressPreservesFamily(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{":8443", "127.0.0.1:8443"}, {"0.0.0.0:8443", "127.0.0.1:8443"},
		{"[::]:8443", "[::1]:8443"}, {"[0:0:0:0:0:0:0:0]:8443", "[::1]:8443"},
		{"127.0.0.2:8443", "127.0.0.2:8443"}, {"[::1]:8443", "[::1]:8443"},
		{"localhost:8443", "localhost:8443"},
	} {
		got, err := localListenerAddress(tc.input)
		if err != nil || got != tc.want {
			t.Fatalf("input=%q got=%q error=%v", tc.input, got, err)
		}
	}
	if _, err := localListenerAddress("bad-address"); err == nil {
		t.Fatal("accepted invalid listener address")
	}
}

func captureHealthCheck(t *testing.T, role, path string) (int, Result, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	code := Check(role, path, true)
	_ = w.Close()
	output, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatal(err)
	}
	return code, result, string(output)
}

func TestHealthCheckIncludesConfiguredQUICAndKeepsErrorsSecret(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		configured, rejected bool
	}{
		{"healthy", true, false}, {"rejected", true, true}, {"disabled", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverCfg, cert, pin := healthTestCertificate(t)
			tcpListener := healthTestListener(t, "tcp", cert, serverCfg.AuthToken, false)
			expectedToken := serverCfg.AuthToken
			if tc.rejected {
				expectedToken = "DIFFERENT_QUIC_HEALTH_TOKEN"
			}
			quicListener := healthTestListener(t, "quic", cert, expectedToken, false)
			serverCfg.ListenAddr = tcpListener.Addr().String()
			clientCfg := &config.ClientConfig{RemoteAddr: tcpListener.Addr().String(), SNI: "health.test",
				AuthToken: serverCfg.AuthToken, TrustMode: "pin", CertificateFingerprint: pin}
			if tc.configured {
				serverCfg.UDPQUICListenAddr = quicListener.Addr().String()
				clientCfg.UDPTransport = "quic"
				clientCfg.UDPQUICRemoteAddr = quicListener.Addr().String()
			}
			for _, role := range []string{"client", "server"} {
				var value any = clientCfg
				if role == "server" {
					value = serverCfg
				}
				data, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), role+".json")
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				code, result, output := captureHealthCheck(t, role, path)
				wantCode := "OK"
				wantExit := 0
				if tc.configured && tc.rejected {
					wantExit = 1
					wantCode = "REMOTE_UDP_QUIC_UNHEALTHY"
					if role == "server" {
						wantCode = "UDP_QUIC_LISTENER_UNHEALTHY"
					}
				}
				if code != wantExit || result.OK != (wantExit == 0) || result.Code != wantCode {
					t.Fatalf("role=%s exit=%d result=%+v", role, code, result)
				}
				if strings.Contains(output, serverCfg.AuthToken) || strings.Contains(output, expectedToken) || strings.Contains(output, pin) || strings.Contains(output, serverCfg.KeyFile) {
					t.Fatal("health diagnostic disclosed private configuration")
				}
			}
		})
	}
}
