package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

type compactHandler struct {
	writer io.Writer
	mu     *sync.Mutex
	level  slog.Leveler
	attrs  []slog.Attr
	group  string
}

func newCompactHandler(w io.Writer, o *slog.HandlerOptions) slog.Handler {
	level := o.Level
	if level == nil {
		level = slog.LevelInfo
	}
	return &compactHandler{writer: w, mu: &sync.Mutex{}, level: level}
}
func (h *compactHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level.Level() }
func (h *compactHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	copy := *h
	copy.attrs = append([]slog.Attr(nil), h.attrs...)
	for _, a := range attrs {
		copy.attrs = append(copy.attrs, h.flatten(a)...)
	}
	return &copy
}
func (h *compactHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	copy := *h
	if copy.group != "" {
		copy.group += "."
	}
	copy.group += name
	return &copy
}
func (h *compactHandler) flatten(a slog.Attr) []slog.Attr {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return nil
	}
	key := a.Key
	if h.group != "" && key != "" {
		key = h.group + "." + key
	}
	if a.Value.Kind() != slog.KindGroup {
		return []slog.Attr{{Key: key, Value: a.Value}}
	}
	child := *h
	child.group = key
	var out []slog.Attr
	for _, nested := range a.Value.Group() {
		out = append(out, child.flatten(nested)...)
	}
	return out
}

var shortKeys = map[string]string{
	"socks_first_byte_duration": "sfirst", "socks_method_duration": "smethod", "socks_auth_duration": "sauth", "socks_request_duration": "sreq",
	"pool_renewed": "renewed", "pool_retry": "retry", "dns_duration": "dns", "target_tcp_duration": "target_tcp", "pool_hits": "hit", "pool_misses": "miss", "pool_fallbacks": "fallbacks", "pool_hit_rate": "hit_pct", "pool_target": "pool_target", "pool_filling": "filling",
	"connection_id": "id", "client_addr": "peer", "remote_addr": "server", "listen_addr": "listen",
	"config_path": "config", "socks_duration": "socks", "tcp_duration": "tcp", "tls_duration": "tls",
	"control_duration": "ctl", "pool_acquire_duration": "take", "setup_duration": "total",
	"auth_duration": "auth", "target_dial_duration": "dial", "connect_duration": "connect",
	"wait_duration": "wait", "reply_duration": "reply", "idle_duration": "idle", "duration": "dur",
	"close_reason": "reason", "error": "err", "max_setup": "setup_max", "max_connections": "conn_max", "max_idle": "idle_max",
}

func printable(s string) string {
	for _, c := range s {
		if unicode.IsSpace(c) || unicode.IsControl(c) || c == '"' || c == '=' {
			return strconv.Quote(s)
		}
	}
	return s
}
func durationText(d time.Duration) string {
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.3f", float64(d)/float64(time.Millisecond)), "0"), ".") + "ms"
}
func byteText(n int64) string {
	if n < 1024 {
		return strconv.FormatInt(n, 10) + "B"
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	v := float64(n) / 1024
	for i, u := range units {
		if v < 1024 || i == len(units)-1 {
			return fmt.Sprintf("%.1f%s", v, u)
		}
		v /= 1024
	}
	return ""
}
func valueText(v slog.Value) string {
	switch v.Kind() {
	case slog.KindDuration:
		return durationText(v.Duration())
	case slog.KindString:
		return printable(v.String())
	case slog.KindTime:
		return v.Time().UTC().Format(time.RFC3339Nano)
	default:
		return printable(fmt.Sprint(v.Any()))
	}
}
func (h *compactHandler) Handle(_ context.Context, record slog.Record) error {
	attrs := append([]slog.Attr(nil), h.attrs...)
	record.Attrs(func(a slog.Attr) bool { attrs = append(attrs, h.flatten(a)...); return true })
	values := make(map[string]slog.Value, len(attrs))
	order := make([]string, 0, len(attrs))
	for _, a := range attrs {
		if _, ok := values[a.Key]; !ok {
			order = append(order, a.Key)
		}
		values[a.Key] = a.Value
	}
	side := values["component"].String()
	switch side {
	case "client":
		side = "C"
	case "server":
		side = "S"
	default:
		side = printable(side)
	}
	var b strings.Builder
	b.WriteString(record.Time.UTC().Format("2006-01-02 15:04:05.000"))
	b.WriteByte(' ')
	b.WriteString(record.Level.String())
	b.WriteByte(' ')
	b.WriteString(side)
	b.WriteByte(' ')
	message := record.Message
	if strings.ContainsAny(message, "\r\n\t") {
		message = strconv.Quote(message)
	}
	b.WriteString(message)
	if target, ok := values["target_addr"]; ok {
		b.WriteByte(' ')
		b.WriteString(valueText(target))
	}
	hit := values["pool_hit"].Kind() == slog.KindBool && values["pool_hit"].Bool()
	for _, key := range order {
		value := values[key]
		if record.Message == "ready" && (key == "connect_duration" || key == "remote_addr") {
			continue
		}
		if record.Message == "stats" && (key == "max_connections" || key == "max_setup" || key == "max_idle") {
			continue
		}
		if key == "component" || key == "target_addr" || key == "pool_fallback" {
			continue
		}
		if hit && (key == "tcp_duration" || key == "tls_duration") {
			continue
		}
		b.WriteByte(' ')
		switch key {
		case "upload_bytes":
			b.WriteString("↑" + byteText(value.Int64()))
		case "download_bytes":
			b.WriteString("↓" + byteText(value.Int64()))
		case "pool_hit", "pool_connection":
			pool := "miss"
			if value.Bool() {
				pool = "hit"
			}
			if fallback, ok := values["pool_fallback"]; ok && fallback.Bool() {
				pool = "fallback"
			}
			b.WriteString("pool=" + pool)
		case "active_connections", "setup_connections", "idle_connections":
			name, maxKey := "active", "max_connections"
			if key == "setup_connections" {
				name, maxKey = "setup", "max_setup"
			}
			if key == "idle_connections" {
				name, maxKey = "idle", "max_idle"
			}
			b.WriteString(name + "=" + valueText(value))
			if maximum, ok := values[maxKey]; ok {
				b.WriteString("/" + valueText(maximum))
			}
		default:
			name := key
			if short, ok := shortKeys[key]; ok {
				name = short
			}
			b.WriteString(printable(name) + "=" + valueText(value))
		}
	}
	b.WriteByte('\n')
	data := b.String()
	h.mu.Lock()
	defer h.mu.Unlock()
	n, err := io.WriteString(h.writer, data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}
