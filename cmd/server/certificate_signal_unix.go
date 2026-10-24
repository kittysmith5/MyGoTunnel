//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

const certificateReloadCapability = "sighup"

func watchCertificateReload(m *certificateManager, logger *slog.Logger) func() {
	hup := make(chan os.Signal, 1)
	stop, done := make(chan struct{}), make(chan struct{})
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-hup:
				changed, err := m.reload()
				if err != nil {
					// Config/parser errors may contain credentials; use fixed fields.
					logger.Warn("certificate reload failed", "reason", "validation")
				} else {
					logger.Info("certificate reloaded", "changed", changed)
				}
			}
		}
	}()
	return func() {
		signal.Stop(hup)
		close(stop)
		<-done
	}
}
