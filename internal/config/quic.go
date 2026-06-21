package config

const (
	defaultKeepAlivePeriodSeconds      = 15
	defaultMaxIdleTimeoutSeconds       = 90
	defaultHandshakeIdleTimeoutSeconds = 10

	defaultInitialStreamReceiveWindow     = 1 << 20
	defaultMaxStreamReceiveWindow         = 16 << 20
	defaultInitialConnectionReceiveWindow = 4 << 20
	defaultMaxConnectionReceiveWindow     = 64 << 20

	defaultMaxIncomingStreams    = 2048
	defaultMaxIncomingUniStreams = -1
	defaultInitialPacketSize     = 1252
)

func applyQUICDefaults(cfg *QUICConfig) {
	if cfg.KeepAlivePeriodSeconds <= 0 {
		cfg.KeepAlivePeriodSeconds = defaultKeepAlivePeriodSeconds
	}

	if cfg.MaxIdleTimeoutSeconds <= 0 {
		cfg.MaxIdleTimeoutSeconds = defaultMaxIdleTimeoutSeconds
	}

	if cfg.HandshakeIdleTimeoutSeconds <= 0 {
		cfg.HandshakeIdleTimeoutSeconds = defaultHandshakeIdleTimeoutSeconds
	}

	if cfg.InitialStreamReceiveWindow == 0 {
		cfg.InitialStreamReceiveWindow = defaultInitialStreamReceiveWindow
	}

	if cfg.MaxStreamReceiveWindow == 0 {
		cfg.MaxStreamReceiveWindow = defaultMaxStreamReceiveWindow
	}

	if cfg.InitialConnectionReceiveWindow == 0 {
		cfg.InitialConnectionReceiveWindow = defaultInitialConnectionReceiveWindow
	}

	if cfg.MaxConnectionReceiveWindow == 0 {
		cfg.MaxConnectionReceiveWindow = defaultMaxConnectionReceiveWindow
	}

	if cfg.MaxIncomingStreams == 0 {
		cfg.MaxIncomingStreams = defaultMaxIncomingStreams
	}

	if cfg.MaxIncomingUniStreams == 0 {
		cfg.MaxIncomingUniStreams = defaultMaxIncomingUniStreams
	}

	if cfg.InitialPacketSize == 0 {
		cfg.InitialPacketSize = defaultInitialPacketSize
	}
}
