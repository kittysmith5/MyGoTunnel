package quicudp

import (
	"errors"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

func TestTransportLimitCloseWithoutStreamReply(t *testing.T) {
	for _, packetRead := range []bool{false, true} {
		name := "control"
		if packetRead {
			name = "packets"
		}
		t.Run(name, func(t *testing.T) {
			p := newTransportPair(t, time.Second)
			if packetRead {
				authorizePair(t, p)
			}
			p.server.RejectLimit()
			var err error
			if packetRead {
				_, err = p.client.ReadPacket()
			} else {
				var b [1]byte
				_, err = p.client.Read(b[:])
			}
			if !errors.Is(err, ErrLimit) {
				t.Fatalf("explicit limit close became %v", err)
			}
		})
	}
}

func TestNormalizeRemoteLimitDoesNotRewriteLocalErrors(t *testing.T) {
	remote := &quic.ApplicationError{ErrorCode: closeLimit, Remote: true}
	if got := normalizeRemoteError(remote); !errors.Is(got, ErrLimit) {
		t.Fatalf("remote limit: %v", got)
	}
	local := &quic.ApplicationError{ErrorCode: closeLimit}
	if got := normalizeRemoteError(local); got != local {
		t.Fatalf("local error was rewritten: %v", got)
	}
}
