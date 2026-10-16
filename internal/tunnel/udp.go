package tunnel

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"mygotunnel/internal/datagram"
)

const MaxDatagramSize = 65000

func SendUDPAssociate(conn net.Conn) error { return writeControl(conn, "UDP\n") }

func SendUDPSetup(conn net.Conn, token string) error {
	if err := validateCommand("AUTH", token); err != nil {
		return err
	}
	return writeControl(conn, "AUTH "+token+"\nUDP\n")
}

// Datagram frames preserve UDP packet boundaries over the tunnel's TCP stream.
func WriteDatagram(w io.Writer, packet []byte) error {
	if len(packet) == 0 || len(packet) > MaxDatagramSize {
		return fmt.Errorf("invalid UDP datagram size %d", len(packet))
	}
	if buffered, ok := w.(*bufio.Writer); ok && buffered.Size() >= 2 {
		// Reuse the existing buffer, including for the length prefix. The caller
		// retains control of batching/Flush; no temporary whole-frame copy.
		if buffered.Available() < 2 {
			if err := buffered.Flush(); err != nil {
				return err
			}
		}
		header := buffered.AvailableBuffer()[:2]
		binary.BigEndian.PutUint16(header, uint16(len(packet)))
		if _, err := buffered.Write(header); err != nil {
			return err
		}
		_, err := buffered.Write(packet)
		return err
	}
	// Keep the length and payload in one write so TLS can use a single record.
	frame := make([]byte, 2+len(packet))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(packet)))
	copy(frame[2:], packet)
	return writeFull(w, frame)
}

// WriteDatagramQueue drops expired packets at dequeue and flushes at most 32
// fresh packets without waiting to fill a batch.
func WriteDatagramQueue(w *bufio.Writer, queue *datagram.Queue) error {
	for i := 0; i < 32; i++ {
		packet, ok := queue.TryPop()
		if !ok {
			break
		}
		if err := WriteDatagram(w, packet.Data); err != nil {
			return err
		}
	}
	return w.Flush()
}

// WriteQueuedDatagrams batches only packets already queued, without waiting for
// more traffic. A bounded batch limits both buffering and flush latency.
func WriteQueuedDatagrams(w *bufio.Writer, first []byte, queued <-chan []byte) error {
	packet := first
	for i := 0; i < 32; i++ {
		if err := WriteDatagram(w, packet); err != nil {
			return err
		}
		if i == 31 {
			break
		}
		select {
		case next, ok := <-queued:
			if !ok {
				return w.Flush()
			}
			packet = next
		default:
			return w.Flush()
		}
	}
	return w.Flush()
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func ReadDatagram(r io.Reader) ([]byte, error) {
	var size [2]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n == 0 || n > MaxDatagramSize {
		return nil, fmt.Errorf("invalid UDP datagram size %d", n)
	}
	packet := make([]byte, n)
	if _, err := io.ReadFull(r, packet); err != nil {
		return nil, err
	}
	return packet, nil
}
