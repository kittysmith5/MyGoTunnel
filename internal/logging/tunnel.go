package logging

import (
	"log/slog"
	"time"

	"mygotunnel/internal/relay"
)

// LogTunnelResult records transfer totals and distinguishes a clean close from
// a relay failure without exposing protocol payloads.
func LogTunnelResult(logger *slog.Logger, result relay.Result, startedAt time.Time, endpointNames ...string) {
	attributes := []any{
		"upload_bytes", result.AToB.Bytes,
		"download_bytes", result.BToA.Bytes,
		"duration", time.Since(startedAt),
	}

	if result.Err != nil {
		phase := result.FailurePhase
		if phase == "" {
			phase = "copy"
		}
		attributes = append(attributes, "failure_phase", phase)
		fault := result.Fault
		endpoint := "unknown"
		if len(endpointNames) >= 2 {
			switch fault.Endpoint {
			case "a":
				endpoint = endpointNames[0]
			case "b":
				endpoint = endpointNames[1]
			}
		}
		if fault.Operation == "" {
			fault.Operation = "unknown"
		}
		attributes = append(attributes, "error_operation", fault.Operation, "error_endpoint", endpoint)
		if fault.Errno != 0 {
			attributes = append(attributes, "error_errno", fault.Errno)
		}
		if fault.LocalAddr != "" {
			attributes = append(attributes, "error_local_addr", fault.LocalAddr, "error_remote_addr", fault.RemoteAddr)
		}
		Failure(logger, result.FailureDirection, result.Err, attributes...)
		return
	}

	logger.Info("closed", append(attributes, "close_reason", "eof")...)
}
