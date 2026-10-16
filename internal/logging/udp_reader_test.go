package logging

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"mygotunnel/internal/datagram"
	"mygotunnel/internal/tunnel"
)

func TestDatagramReaderTerminationLoggingAndCounters(t *testing.T) {
	for _, tc := range []struct {
		name         string
		frame        []byte
		exhausted    bool
		completeDrop bool
		packets      int
		truncated    bool
	}{
		{name: "frame_boundary"},
		{name: "complete_frame", frame: []byte{0, 1, 'a'}, packets: 1},
		{name: "half_prefix", frame: []byte{0}, truncated: true},
		{name: "missing_body", frame: []byte{0, 5}, truncated: true},
		{name: "partial_body", frame: []byte{0, 5, 'a'}, truncated: true},
		{name: "resource_missing_body", frame: []byte{0, 5}, exhausted: true, truncated: true},
		{name: "resource_partial_body", frame: []byte{0, 5, 'a'}, exhausted: true, truncated: true},
		{name: "resource_drop_then_recover", frame: []byte{0, 1, 'a', 0, 1, 'b'}, exhausted: true, completeDrop: true, packets: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resources := datagram.NewResources(1, 512)
			defer resources.Close()
			var held datagram.Packet
			if tc.exhausted {
				var err error
				held, err = resources.Borrow(1)
				if err != nil {
					t.Fatal(err)
				}
				defer held.Release()
			}
			reader := tunnel.NewDatagramReader(bufio.NewReader(bytes.NewReader(tc.frame)), resources)
			var readErr error
			packets, drops := 0, 0
			for {
				packet, err := reader.ReadPacket()
				if errors.Is(err, datagram.ErrResourceLimit) {
					if !tc.completeDrop || drops != 0 {
						t.Fatal("unexpected complete-frame resource rejection", err)
					}
					drops++
					held.Release()
					continue
				}
				if err != nil {
					readErr = err
					break
				}
				packets++
				packet.Release()
			}
			held.Release()
			if packets != tc.packets || (drops == 1) != tc.completeDrop {
				t.Fatalf("packets=%d drops=%d, want packets=%d completeDrop=%t", packets, drops, tc.packets, tc.completeDrop)
			}
			wantReason, wantMessage, wantLevel := "eof", "closed", "INFO"
			wantEOF, wantTruncated, wantErrors := uint64(1), uint64(0), uint64(0)
			if tc.truncated {
				if !errors.Is(readErr, io.ErrUnexpectedEOF) {
					t.Fatalf("ReadPacket() error = %v, want truncated frame", readErr)
				}
				wantReason, wantMessage, wantLevel = "truncated", "failed", "WARN"
				wantEOF, wantTruncated, wantErrors = 0, 1, 1
			} else if !errors.Is(readErr, io.EOF) {
				t.Fatalf("ReadPacket() error = %v, want boundary EOF", readErr)
			}
			var output bytes.Buffer
			logger, err := New(&output, Options{Component: "client", Format: "json", Level: "info"})
			if err != nil {
				t.Fatal(err)
			}
			LogUDPResult(logger, resources, "udp_tunnel_read", readErr, tunnel.DatagramWriteStats{})
			stats := resources.Stats()
			ends := stats.Terminations
			if stats.Sessions != 1 || stats.SessionErrors != wantErrors || ends.EOF != wantEOF || ends.Truncated != wantTruncated {
				t.Fatal("reader result counted under wrong termination cause", stats)
			}
			if ends.EOF+ends.Timeout+ends.Reset+ends.Truncated+ends.Canceled+ends.Closed+ends.Other != stats.Sessions || stats.WriteErrors != 0 || stats.WriteTimeouts != 0 {
				t.Fatal("termination counters overlap", stats)
			}
			if stats.BufferBytes != stats.CachedBytes {
				t.Fatal("reader retained a buffer owner", stats)
			}
			var record map[string]any
			if err := json.Unmarshal(output.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
			if record["close_reason"] != wantReason || record["msg"] != wantMessage || record["level"] != wantLevel || record["stage"] != "udp_tunnel_read" {
				t.Fatal("reader result logged with wrong severity or reason", record)
			}
		})
	}
}
