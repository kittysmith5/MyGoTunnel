package mux

import (
	"encoding/binary"
	"io"
)

/*
+----------+----------+----------+----------+
| StreamID | Type     | Length   | Payload  |
| 4 bytes  | 1 byte   | 4 bytes  | N bytes  |
+----------+----------+----------+----------+
*/
const frameHeaderSize = 9

type Frame struct {
	StreamID uint32
	Type     FrameType
	Payload  []byte
}

func writeFrame(w io.Writer, f Frame) error {
	if len(f.Payload) > DefaultMaxFrameSize {
		return ErrInvalidFrame
	}

	header := make([]byte, frameHeaderSize)

	binary.BigEndian.PutUint32(header[0:4], f.StreamID)
	header[4] = byte(f.Type)
	binary.BigEndian.PutUint32(header[5:9], uint32(len(f.Payload)))

	if err := writeFull(w, header); err != nil {
		return err
	}

	if len(f.Payload) > 0 {
		if err := writeFull(w, f.Payload); err != nil {
			return err
		}
	}

	return nil
}

func readFrame(r io.Reader) (Frame, error) {
	header := make([]byte, frameHeaderSize)

	if _, err := io.ReadFull(r, header); err != nil {
		return Frame{}, err
	}

	streamID := binary.BigEndian.Uint32(header[0:4])
	frameType := FrameType(header[4])
	length := binary.BigEndian.Uint32(header[5:9])

	if length > DefaultMaxFrameSize {
		return Frame{}, ErrInvalidFrame
	}

	payload := make([]byte, length)

	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return Frame{}, err
		}
	}

	return Frame{
		StreamID: streamID,
		Type:     frameType,
		Payload:  payload,
	}, nil
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}

		if n == 0 {
			return io.ErrShortWrite
		}

		p = p[n:]
	}

	return nil
}
