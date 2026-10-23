package config

import (
	"errors"
	"io"
	"os"
)

const DefaultHTTPSIndex = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Welcome</title></head><body><h1>Welcome</h1><p>This site is available.</p></body></html>\n"

// HTTPSConfig enables the optional, legacy-compatible HTTPS fallback entrance.
type HTTPSConfig struct {
	Enabled           bool   `json:"enabled"`
	IndexFile         string `json:"index_file,omitempty"`
	MaxConnections    int    `json:"max_connections,omitempty"`
	MaxPreAuthPerIP   int    `json:"max_pre_auth_per_ip,omitempty"`
	PreAuthRatePerIP  int    `json:"pre_auth_rate_per_ip,omitempty"`
	PreAuthBurstPerIP int    `json:"pre_auth_burst_per_ip,omitempty"`
	index             []byte
}

func (c *HTTPSConfig) validate() error {
	for _, n := range []int{c.MaxConnections, c.MaxPreAuthPerIP, c.PreAuthRatePerIP, c.PreAuthBurstPerIP} {
		if n < 0 || n > 10000 {
			return errors.New("invalid https_entry limits")
		}
	}
	if !c.Enabled || c.IndexFile == "" {
		return nil
	}
	before, err := os.Lstat(c.IndexFile)
	if err != nil || !before.Mode().IsRegular() || before.Size() > 65536 {
		return errors.New("https_entry index must be a regular file of at most 65536 bytes")
	}
	f, err := os.Open(c.IndexFile)
	if err != nil {
		return errors.New("cannot open https_entry index")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return errors.New("https_entry index changed while opening")
	}
	c.index, err = io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(c.index) > 65536 {
		return errors.New("cannot read bounded https_entry index")
	}
	return nil
}

// HTML is an immutable startup snapshot; requests never access the filesystem.
func (c HTTPSConfig) HTML() []byte {
	if c.index != nil {
		return c.index
	}
	return []byte(DefaultHTTPSIndex)
}

// Effective resolves limits against the actual server CLI limits.
func (c HTTPSConfig) Effective(maxSetup, maxConnections int) (HTTPSConfig, error) {
	if maxSetup < 1 || maxConnections < 1 || c.MaxPreAuthPerIP > maxSetup || c.MaxConnections > maxConnections {
		return c, errors.New("https_entry limits exceed server limits")
	}
	if c.MaxPreAuthPerIP == 0 {
		c.MaxPreAuthPerIP = min(32, max(1, (maxSetup+3)/4))
	}
	if c.MaxConnections == 0 {
		c.MaxConnections = min(64, maxConnections)
	}
	if c.PreAuthRatePerIP == 0 {
		c.PreAuthRatePerIP = 20
	}
	if c.PreAuthBurstPerIP == 0 {
		c.PreAuthBurstPerIP = 40
	}
	return c, nil
}
