package logging

import (
	"log/slog"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/tunnel"
)

func UDPResourceAttrs(resources *datagram.Resources) []any {
	s := resources.Stats()
	return []any{"udp_sockets", s.Sockets, "udp_max_sockets", s.MaxSockets,
		"udp_buffer_bytes", s.BufferBytes, "udp_cached_bytes", s.CachedBytes, "udp_buffer_peak_bytes", s.PeakBytes,
		"udp_resident_bytes", s.ResidentBytes, "udp_resident_limit_bytes", s.ResidentLimit,
		"udp_transient_reserve_bytes", s.TransientReserve, "udp_resident_rejected", s.ResidentRejected,
		"udp_memory_limit_bytes", s.MemoryLimit, "udp_socket_rejected", s.SocketRejected, "udp_memory_rejected", s.MemoryRejected,
		"udp_sessions_closed", s.Sessions, "udp_session_errors", s.SessionErrors, "udp_tunnel_write_failures", s.WriteErrors, "udp_write_timeouts", s.WriteTimeouts,
		"udp_control_errors", s.ControlSessionErrors, "udp_data_errors", s.DataSessionErrors,
		"udp_end_eof", s.Terminations.EOF, "udp_end_timeout", s.Terminations.Timeout, "udp_end_reset", s.Terminations.Reset,
		"udp_end_truncated", s.Terminations.Truncated, "udp_end_canceled", s.Terminations.Canceled, "udp_end_closed", s.Terminations.Closed, "udp_end_error", s.Terminations.Other}
}

// LogUDPResult preserves the first termination cause, before deliberate I/O
// interruption creates secondary closed/timeout errors in the other workers.
func LogUDPResult(logger *slog.Logger, resources *datagram.Resources, stage string, err error, writes tunnel.DatagramWriteStats, attrs ...any) {
	reason := Reason(err)
	failed := reason != "eof"
	writeFailed := failed && stage == "udp_tunnel_write"
	scope := "data"
	if stage == "udp_control" {
		scope = "control"
	}
	resources.RecordSession(reason, writeFailed, scope)
	attrs = append(attrs, "transport", "udp", "udp_termination_scope", scope, "udp_tunnel_write_calls", writes.Calls, "udp_tunnel_write_errors", writes.Errors,
		"udp_tunnel_write_timeouts", writes.Timeouts, "udp_tunnel_write_max_duration", writes.MaxDuration)
	if failed {
		Failure(logger, stage, err, attrs...)
		return
	}
	logger.Info("closed", append(attrs, "stage", stage, "close_reason", reason)...)
}
