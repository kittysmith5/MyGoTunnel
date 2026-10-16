package tunnel

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"mygotunnel/internal/datagram"
)

func TestDatagramQueueFlushBoundsAndExpiry(t *testing.T) {
	q := datagram.NewQueue(64, 1024, datagram.DefaultMaxAge, nil)
	defer q.Close()
	// Already-expired packets are rejected before taking queue capacity.
	q.Push(datagram.Packet{Data: []byte("old"), At: time.Now().Add(-time.Second)})
	for i := 0; i < 40; i++ {
		q.PushCopy([]byte{byte(i)})
	}
	var wire bytes.Buffer
	writer := bufio.NewWriterSize(&wire, 128)
	for _, count := range []int{32, 8} {
		if err := WriteDatagramQueue(writer, q); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < count; i++ {
			got, err := ReadDatagram(&wire)
			offset := 0
			if count == 8 {
				offset = 32
			}
			if err != nil || !bytes.Equal(got, []byte{byte(i + offset)}) {
				t.Fatalf("batch contents: %v %v", got, err)
			}
		}
		if wire.Len() != 0 || writer.Buffered() != 0 {
			t.Fatal("batch not flushed")
		}
	}
	if q.Stats().ExpiredDrops != 1 || q.Stats().Packets != 0 {
		t.Fatal(q.Stats())
	}
}

type datagramFailWriter struct{}

func (datagramFailWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestBufferedDatagramFlushErrorPropagates(t *testing.T) {
	q := datagram.NewQueue(1, 1024, datagram.DefaultMaxAge, nil)
	defer q.Close()
	q.PushCopy([]byte("packet"))
	if err := WriteDatagramQueue(bufio.NewWriter(datagramFailWriter{}), q); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("flush error lost", err)
	}
}
