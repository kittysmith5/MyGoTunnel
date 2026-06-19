package mux

import (
	"io"
	"sync"
)

type Stream struct {
	id   uint32
	sess *Session

	readCh  chan []byte
	readMu  sync.Mutex
	readBuf []byte

	writeMu sync.Mutex

	closeOnce sync.Once
	closeCh   chan struct{}
}

func newStream(id uint32, sess *Session) *Stream {
	return &Stream{
		id:      id,
		sess:    sess,
		readCh:  make(chan []byte, DefaultReadChanSize),
		closeCh: make(chan struct{}),
	}
}

func (s *Stream) ID() uint32 {
	return s.id
}

func (s *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.readMu.Lock()
	defer s.readMu.Unlock()

	if len(s.readBuf) > 0 {
		n := copy(p, s.readBuf)
		s.readBuf = s.readBuf[n:]
		return n, nil
	}

	// 优先读已经到达的数据，避免 closeCh 和 readCh 同时 ready 时丢数据
	select {
	case data := <-s.readCh:
		return s.consumeReadData(p, data), nil
	default:
	}

	select {
	case data := <-s.readCh:
		return s.consumeReadData(p, data), nil

	case <-s.closeCh:
		return 0, io.EOF
	}
}

func (s *Stream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if s.isClosed() {
		return 0, ErrStreamClosed
	}

	total := 0

	for total < len(p) {
		chunkSize := len(p) - total
		if chunkSize > DefaultMaxFrameSize {
			chunkSize = DefaultMaxFrameSize
		}

		payload := make([]byte, chunkSize)
		copy(payload, p[total:total+chunkSize])

		err := s.sess.writeFrame(Frame{
			StreamID: s.id,
			Type:     FrameTypeData,
			Payload:  payload,
		})

		if err != nil {
			if total > 0 {
				return total, err
			}
			return 0, err
		}

		total += chunkSize
	}

	return total, nil
}

func (s *Stream) Close() error {
	var err error

	s.closeOnce.Do(func() {
		close(s.closeCh)
		s.sess.removeStream(s.id)

		err = s.sess.writeFrame(Frame{
			StreamID: s.id,
			Type:     FrameTypeClose,
		})
	})

	return err
}

func (s *Stream) pushData(data []byte) error {
	if s.isClosed() {
		return ErrStreamClosed
	}

	select {
	case s.readCh <- data:
		return nil

	case <-s.closeCh:
		return ErrStreamClosed

	case <-s.sess.closeCh:
		return ErrSessionClosed
	}
}

func (s *Stream) closeRemote() {
	s.closeOnce.Do(func() {
		close(s.closeCh)
	})
}

func (s *Stream) consumeReadData(p []byte, data []byte) int {
	n := copy(p, data)

	if n < len(data) {
		s.readBuf = append(s.readBuf, data[n:]...)
	}

	return n
}

func (s *Stream) isClosed() bool {
	select {
	case <-s.closeCh:
		return true
	default:
		return false
	}
}

var _ io.ReadWriteCloser = (*Stream)(nil)
