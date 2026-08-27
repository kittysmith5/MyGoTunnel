package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

const (
	FormatText = "text"
	FormatJSON = "json"
)

type Options struct {
	Component string
	Level     string
	Format    string
}

func New(writer io.Writer, options Options) (*slog.Logger, error) {
	if writer == nil {
		return nil, fmt.Errorf("log writer is nil")
	}

	component := strings.TrimSpace(options.Component)
	if component == "" {
		return nil, fmt.Errorf("log component is empty")
	}

	levelText := strings.TrimSpace(options.Level)
	if levelText == "" {
		levelText = "info"
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(levelText)); err != nil {
		return nil, fmt.Errorf("invalid log level %q: %w", options.Level, err)
	}

	format := strings.ToLower(strings.TrimSpace(options.Format))
	if format == "" {
		format = FormatText
	}

	handlerOptions := &slog.HandlerOptions{Level: level}
	var handler slog.Handler

	switch format {
	case FormatText:
		handler = slog.NewTextHandler(writer, handlerOptions)
	case FormatJSON:
		handler = slog.NewJSONHandler(writer, handlerOptions)
	default:
		return nil, fmt.Errorf("invalid log format %q: use %q or %q", options.Format, FormatText, FormatJSON)
	}

	return slog.New(handler).With(slog.String("component", component)), nil
}
