// Package operations implements explicit, secret-free administrative checks.
package operations

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
// Health verifies the remote authenticated TLS control channel for clients;
// server health checks its configured TCP listener, not a complete proxy request.
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
					entry, e := preconnect.Prepare(ctx, cfg)
					cancel()
					if e != nil {
						r.OK = false
						r.Code = "REMOTE_CONTROL_UNHEALTHY"
					} else {
						entry.Conn.Close()
					}
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
							host, port, _ := net.SplitHostPort(cfg.ListenAddr)
							if host == "" || host == "0.0.0.0" || host == "::" {
								host = "127.0.0.1"
							}
							c, e := net.DialTimeout("tcp", net.JoinHostPort(host, port), 3*time.Second)
							if e != nil {
								r.OK = false
								r.Code = "LISTENER_UNHEALTHY"
							} else {
								c.Close()
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
	if json.NewEncoder(os.Stdout).Encode(r) != nil {
		return 1
	}
	if !r.OK {
		return 1
	}
	return 0
}
