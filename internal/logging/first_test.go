package logging

import (
	"bytes"
	"mygotunnel/internal/relay"
	"strings"
	"testing"
	"time"
)

func TestFirstDataFieldsAndDefaultNoExtraEvents(t *testing.T) {
	var out bytes.Buffer
	l, e := New(&out, Options{Format: "json", Level: "info", Component: "client"})
	if e != nil {
		t.Fatal(e)
	}
	FirstDataObserver(l)("up", time.Millisecond)
	if out.Len() != 0 {
		t.Fatal("default first-data emitted an extra log")
	}
	LogTunnelResult(l, relay.Result{AToB: relay.DirectionResult{FirstByteSeen: true, FirstByteDuration: 2 * time.Millisecond}}, time.Now())
	if !strings.Contains(out.String(), `"first_up_duration":2000000`) || strings.Contains(out.String(), `first_down_duration`) {
		t.Fatal(out.String())
	}
}
