// Package operations implements explicit, secret-free administrative checks.
package operations

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/preconnect"
)

type Result struct {
	OK       bool     `json:"ok"`
	Role     string   `json:"role"`
	Check    string   `json:"check"`
	Code     string   `json:"code"`
	Warnings []string `json:"warnings,omitempty"`
}

// Check prints fixed diagnostic codes only: parser errors can contain credentials.
// Health verifies the remote authenticated TLS control channel for clients and
// the configured TCP listener for servers. Configured QUIC UDP transport also
// requires an authenticated QUIC UDP setup; no business packets are sent.
func Check(role, path string, health bool) int {
	r := Result{Role: role, Check: "config", Code: "CONFIG_INVALID"}
	if health {
		r.Check = "health"
	}
	if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0077 != 0 {
		r.Warnings = append(r.Warnings, "CONFIG_PERMISSIONS_NOT_PRIVATE")
	}
	if role == "client" {
		cfg, err := config.LoadClientConfig(path)
		if err == nil {
			if _, _, err = net.SplitHostPort(cfg.LocalAddr); err == nil {
				r.OK = true
				r.Code = "OK"
				if cfg.SOCKSAuth == nil {
					r.Warnings = append(r.Warnings, "SOCKS_AUTH_DISABLED")
				}
				if health {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					if cfg.TCPTransportMode() == "quic" {
						if e := probeTCPStreamControl(ctx, cfg.TCPQUICRemote(), cfg.SNI, cfg.CertificateFingerprint, cfg.AuthToken); e != nil {
							r.OK = false
							r.Code = "REMOTE_TCP_QUIC_UNHEALTHY"
						}
					} else {
						entry, e := preconnect.Prepare(ctx, cfg)
						if e != nil {
							r.OK = false
							r.Code = "REMOTE_CONTROL_UNHEALTHY"
						} else {
							_ = entry.Conn.Close()
						}
					}
					if r.OK && cfg.TCPTransportMode() == "quic" && cfg.UDPTransportMode() == "tcp" {
						entry, e := preconnect.Prepare(ctx, cfg)
						if e != nil {
							r.OK = false
							r.Code = "REMOTE_CONTROL_UNHEALTHY"
						} else {
							_ = entry.Conn.Close()
						}
					}
					if r.OK && cfg.UDPTransportMode() == "quic" {
						if e := probeQUICControl(ctx, cfg.UDPQUICRemote(), cfg.SNI, cfg.CertificateFingerprint, cfg.AuthToken); e != nil {
							r.OK = false
							r.Code = "REMOTE_UDP_QUIC_UNHEALTHY"
						}
					}

					cancel()
				}
			}
		}
	} else {
		cfg, err := config.LoadServerConfig(path)
		if err == nil {
			if _, _, err = net.SplitHostPort(cfg.ListenAddr); err == nil {
				cert, e := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
				if e == nil {
					leaf, e := x509.ParseCertificate(cert.Certificate[0])
					if e == nil && time.Now().Before(leaf.NotAfter) && time.Now().After(leaf.NotBefore) {
						r.OK = true
						r.Code = "OK"
						if time.Until(leaf.NotAfter) < 30*24*time.Hour {
							r.Warnings = append(r.Warnings, "CERT_EXPIRES_WITHIN_30_DAYS")
						}
						if health {
							localAddr, _ := localListenerAddress(cfg.ListenAddr)
							c, e := net.DialTimeout("tcp", localAddr, 3*time.Second)
							if e != nil {
								r.OK = false
								r.Code = "LISTENER_UNHEALTHY"
							} else {
								_ = c.Close()
								if cfg.UDPQUICListenAddr != "" {
									localAddr, _ := localListenerAddress(cfg.UDPQUICListenAddr)
									pin := sha256.Sum256(cert.Certificate[0])
									ctx, cancel := context.WithTimeout(context.Background(), quicHealthTimeout)
									e := probeQUICControl(ctx, localAddr, "", hex.EncodeToString(pin[:]), cfg.AuthToken)
									cancel()
									if e != nil {
										r.OK = false
										r.Code = "UDP_QUIC_LISTENER_UNHEALTHY"
									}
								}
							}
						}
					} else {
						r.Code = "CERT_INVALID_OR_EXPIRED"
					}
				} else {
					r.Code = "CERT_KEY_INVALID"
				}
			}
		}
	}
	if role == "server" && health && r.OK {
		cfg, e := config.LoadServerConfig(path)
		if e == nil && cfg.TCPQUICListenAddr != "" {
			cert, e := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
			if e != nil {
				r.OK = false
				r.Code = "CERT_KEY_INVALID"
			} else {
				address, e := localListenerAddress(cfg.TCPQUICListenAddr)
				if e != nil {
					r.OK = false
					r.Code = "TCP_QUIC_LISTENER_UNHEALTHY"
				} else {
					pin := sha256.Sum256(cert.Certificate[0])
					ctx, cancel := context.WithTimeout(context.Background(), quicHealthTimeout)
					e = probeTCPStreamControl(ctx, address, "", hex.EncodeToString(pin[:]), cfg.AuthToken)
					cancel()
					if e != nil {
						r.OK = false
						r.Code = "TCP_QUIC_LISTENER_UNHEALTHY"
					}
				}
			}
		}
	}

	if json.NewEncoder(os.Stdout).Encode(r) != nil {
		return 1
	}
	if !r.OK {
		return 1
	}
	return 0
}
