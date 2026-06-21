package quiccfg

import (
	"time"

	"mygotunnel/internal/config"

	"github.com/quic-go/quic-go"
)

func Build(cfg config.QUICConfig) *quic.Config {
	return &quic.Config{
		KeepAlivePeriod:                time.Duration(cfg.KeepAlivePeriodSeconds) * time.Second,
		MaxIdleTimeout:                 time.Duration(cfg.MaxIdleTimeoutSeconds) * time.Second,
		HandshakeIdleTimeout:           time.Duration(cfg.HandshakeIdleTimeoutSeconds) * time.Second,
		InitialStreamReceiveWindow:     cfg.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         cfg.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: cfg.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     cfg.MaxConnectionReceiveWindow,
		MaxIncomingStreams:             cfg.MaxIncomingStreams,
		MaxIncomingUniStreams:          cfg.MaxIncomingUniStreams,
		InitialPacketSize:              cfg.InitialPacketSize,
		DisablePathMTUDiscovery:        cfg.DisablePathMTUDiscovery,
	}
}
