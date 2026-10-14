//go:build !linux

package diagnostics

func cpuSeconds() (float64, bool) { return 0, false }
