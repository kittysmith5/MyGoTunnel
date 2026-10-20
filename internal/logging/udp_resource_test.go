package logging

import (
	"bytes"
	"encoding/json"
	"testing"

	"mygotunnel/internal/datagram"
)

func TestUDPResidentResourceStatsRemainVisibleAndDoNotDoubleCount(t *testing.T) {
	r := datagram.NewResources(4, 4*65536)
	defer r.Close()
	first, err := r.BorrowResident(65536)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Release()
	second, err := r.BorrowResident(65536)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Release()
	if packet, err := r.BorrowResident(65536); err == nil {
		packet.Release()
		t.Fatal("resident allocation consumed frame reserve")
	}
	for _, format := range []string{FormatJSON, FormatText} {
		var out bytes.Buffer
		logger, err := New(&out, Options{Component: "server", Format: format})
		if err != nil {
			t.Fatal(err)
		}
		logger.Info("stats", UDPResourceAttrs(r)...)
		if format == FormatJSON {
			var record map[string]any
			if err = json.Unmarshal(out.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
			for key, want := range map[string]float64{"udp_resident_bytes": 131072, "udp_resident_limit_bytes": 131072, "udp_transient_reserve_bytes": 131072, "udp_resident_rejected": 1, "udp_memory_rejected": 1} {
				if record[key] != want {
					t.Fatalf("%s=%v, want %v", key, record[key], want)
				}
			}
		} else if !bytes.Contains(out.Bytes(), []byte("udp_resident_rejected=1")) || !bytes.Contains(out.Bytes(), []byte("udp_transient_reserve_bytes=131072")) {
			t.Fatal(out.String())
		}
	}
}
