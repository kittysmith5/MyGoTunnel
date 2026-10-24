//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package main

import "log/slog"

const certificateReloadCapability = "unsupported"

func watchCertificateReload(*certificateManager, *slog.Logger) func() { return func() {} }
