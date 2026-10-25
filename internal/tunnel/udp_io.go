package tunnel

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"mygotunnel/internal/datagram"
)

// DatagramReader reuses its length prefix and transfers a pooled packet to the
// caller. A resource rejection consumes the frame, keeping the stream aligned.
type DatagramReader struct {
	reader    *bufio.Reader
	resources *datagram.Resources
	size      [2]byte
}

func NewDatagramReader(reader *bufio.Reader, resources *datagram.Resources) *DatagramReader {
	return &DatagramReader{reader: reader, resources: resources}
}

// PacketReader preserves packet ownership for transports that already provide
// message boundaries. The TCP path retains its existing buffered framing.
type PacketReader interface {
	ReadPacket() (datagram.Packet, error)
}

func NewPacketReader(conn net.Conn, reader *bufio.Reader, resources *datagram.Resources) PacketReader {
	if packets, ok := conn.(PacketReader); ok {
		return packets
	}
	return NewDatagramReader(reader, resources)
}

// EnableDatagrams is called only after authentication and the UDP command have
// succeeded. The optional control-stream monitor then owns subsequent reads.
func EnableDatagrams(conn net.Conn) {
	if packets, ok := conn.(interface{ EnableDatagrams() }); ok {
		packets.EnableDatagrams()
	}
}

// DatagramTransportAttrs supplements the shared UDP counters with bounded
// transport-specific drops. Call after the association's workers have stopped.
func DatagramTransportAttrs(conn net.Conn) []any {
	if packets, ok := conn.(interface{ DatagramAttrs() []any }); ok {
		return packets.DatagramAttrs()
	}
	return nil
}

// DatagramQueueWriter keeps TCP batching intact and sends each queued packet
// separately when the transport provides unreliable datagrams.
type DatagramQueueWriter struct {
	*DatagramWriter
	buffered *bufio.Writer
	packets  interface{ WritePacket([]byte) error }
}

func NewDatagramQueueWriter(conn net.Conn, timeout time.Duration) *DatagramQueueWriter {
	w := &DatagramQueueWriter{DatagramWriter: NewDatagramWriter(conn, timeout)}
	w.packets, _ = conn.(interface{ WritePacket([]byte) error })
	if w.packets == nil {
		w.buffered = bufio.NewWriterSize(w.DatagramWriter, 32*1024)
	}
	return w
}

func (w *DatagramQueueWriter) WriteQueue(queue interface {
	TryPop() (datagram.Packet, bool)
}) error {
	if w.packets == nil {
		return WriteDatagramQueue(w.buffered, queue)
	}
	for i := 0; i < 32; i++ {
		packet, ok := queue.TryPop()
		if !ok {
			return nil
		}
		started := time.Now()
		err := w.conn.SetWriteDeadline(started.Add(w.timeout))
		if err == nil {
			err = w.packets.WritePacket(packet.Data)
		}
		packet.Release()
		if err == nil {
			err = w.conn.SetWriteDeadline(time.Time{})
		}
		w.record(started, err)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *DatagramReader) ReadPacket() (datagram.Packet, error) {
	if _, err := io.ReadFull(r.reader, r.size[:]); err != nil {
		return datagram.Packet{}, err
	}
	n := int(binary.BigEndian.Uint16(r.size[:]))
	if n == 0 || n > MaxDatagramSize {
		return datagram.Packet{}, fmt.Errorf("invalid UDP datagram size %d", n)
	}
	p, err := r.resources.Borrow(n)
	if err != nil {
		if _, discardErr := r.reader.Discard(n); discardErr != nil {
			if errors.Is(discardErr, io.EOF) {
				discardErr = io.ErrUnexpectedEOF
			}
			return datagram.Packet{}, discardErr
		}
		return datagram.Packet{}, err
	}
	if _, err = io.ReadFull(r.reader, p.Data); err != nil {
		p.Release()
		// EOF is clean only before a frame's prefix. Once the length has
		// arrived, even a completely absent body is a truncated frame.
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return datagram.Packet{}, err
	}
	return p, nil
}

type DatagramWriteStats struct {
	Calls, Errors, Timeouts uint64
	MaxDuration             time.Duration
}

// DatagramWriter is single-writer. Each TLS Write has its own time limit;
// queue age and read/idle lifetimes are independent. On any error the caller
// must abort the association: a partially written frame cannot be skipped.
type DatagramWriter struct {
	conn    net.Conn
	timeout time.Duration
	stats   DatagramWriteStats
}

func NewDatagramWriter(conn net.Conn, timeout time.Duration) *DatagramWriter {
	return &DatagramWriter{conn: conn, timeout: timeout}
}

func (w *DatagramWriter) Write(p []byte) (int, error) {
	started := time.Now()
	err := w.conn.SetWriteDeadline(started.Add(w.timeout))
	var n int
	if err == nil {
		n, err = w.conn.Write(p)
	}
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err == nil {
		// TLS reads may themselves write protocol messages (e.g. KeyUpdate).
		// Do not leave an expired write deadline behind while the stream is idle.
		err = w.conn.SetWriteDeadline(time.Time{})
	}
	w.record(started, err)
	return n, err
}

func (w *DatagramWriter) record(started time.Time, err error) {
	w.stats.Calls++
	w.stats.MaxDuration = max(w.stats.MaxDuration, time.Since(started))
	if err != nil {
		w.stats.Errors++
		var e net.Error
		if errors.As(err, &e) && e.Timeout() {
			w.stats.Timeouts++
		}
	}
}

// Stats is read after the writer worker has exited.
func (w *DatagramWriter) Stats() DatagramWriteStats { return w.stats }

// AbortDatagramConn interrupts I/O without waiting for a TLS close notification.
func AbortDatagramConn(conn net.Conn) {
	if wrapped, ok := conn.(interface{ NetConn() net.Conn }); ok {
		_ = wrapped.NetConn().Close()
	} else {
		_ = conn.Close()
	}
}
