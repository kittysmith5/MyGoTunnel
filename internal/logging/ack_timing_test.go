package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPreparedAckTimingFormats(t *testing.T) {
	for _, format := range []string{FormatText, FormatJSON} {
		t.Run(format, func(t *testing.T) {
			var out bytes.Buffer
			logger, err := New(&out, Options{Component: "client", Format: format})
			if err != nil {
				t.Fatal(err)
			}
			logger.Info("ready", "pool_ack_duration", 1250*time.Microsecond)
			if format == FormatText {
				if !strings.Contains(out.String(), "ack=1.25ms") {
					t.Fatal(out.String())
				}
				return
			}
			var record map[string]any
			if err := json.Unmarshal(out.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
			if record["pool_ack_duration"] != float64(1250000) {
				t.Fatal(record)
			}
		})
	}
}
