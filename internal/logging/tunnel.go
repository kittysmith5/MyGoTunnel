package logging

import (
	"log/slog"
	"time"

	"mygotunnel/internal/relay"
)

// LogTunnelResult records transfer totals and distinguishes a clean close from
// a relay failure without exposing protocol payloads.
func LogTunnelResult(logger *slog.Logger, result relay.Result, startedAt time.Time) {
	attributes := []any{
		"upload_bytes", result.AToB.Bytes,
		"download_bytes", result.BToA.Bytes,
		"duration", time.Since(startedAt),
	}

	if result.Err != nil {
		Failure(logger, result.FailureDirection, result.Err, attributes...)
		return
	}

	logger.Info("closed", append(attributes, "close_reason", "eof")...)
}
