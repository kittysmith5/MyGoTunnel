package mux

import (
	"io"
	"sync"
)

type Session struct {
	conn io.ReadWriteCloser
	mode SessionMode

	writeMu sync.Mutex

	streamMu sync.Mutex
	streams  map[uint32]*Stream
	nextID   uint32

	acceptCh chan *Stream

	closeOnce sync.Once
	closeCh   chan struct{}
}

func NewSession(conn io.ReadWriteCloser, mode SessionMode) *Session {
	nextID := uint32(1)

	if mode == ModeServer {
		nextID = 2
	}

	s := &Session{
		conn:     conn,
		mode:     mode,
		streams:  make(map[uint32]*Stream),
		nextID:   nextID,
		acceptCh: make(chan *Stream, DefaultAcceptSize),
		closeCh:  make(chan struct{}),
	}

	go s.readLoop()

	return s
}

func (s *Session) OpenStream() (*Stream, error) {
	if s.isClosed() {
		return nil, ErrSessionClosed
	}

	stream := s.createLocalStream()

	err := s.writeFrame(Frame{
		StreamID: stream.id,
		Type:     FrameTypeOpen,
	})

	if err != nil {
		s.removeStream(stream.id)
		stream.closeRemote()
		return nil, err
	}

	return stream, nil
}

func (s *Session) AcceptStream() (*Stream, error) {
	select {
	case stream := <-s.acceptCh:
		if stream == nil {
			return nil, ErrSessionClosed
		}
		return stream, nil

	case <-s.closeCh:
		return nil, ErrSessionClosed
	}
}

func (s *Session) Close() error {
	var err error

	s.closeOnce.Do(func() {
		close(s.closeCh)
		err = s.conn.Close()

		s.streamMu.Lock()
		for _, stream := range s.streams {
			stream.closeRemote()
		}
		s.streams = make(map[uint32]*Stream)
		s.streamMu.Unlock()
	})

	return err
}

func (s *Session) writeFrame(f Frame) error {
	if s.isClosed() {
		return ErrSessionClosed
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	return writeFrame(s.conn, f)
}

func (s *Session) readLoop() {
	for {
		frame, err := readFrame(s.conn)
		if err != nil {
			_ = s.Close()
			return
		}

		if err := s.handleFrame(frame); err != nil {
			_ = s.Close()
			return
		}
	}
}

func (s *Session) handleFrame(frame Frame) error {
	switch frame.Type {
	case FrameTypeOpen:
		return s.handleOpen(frame)

	case FrameTypeData:
		return s.handleData(frame)

	case FrameTypeClose:
		return s.handleClose(frame)

	case FrameTypeError:
		return s.handleClose(frame)

	default:
		return ErrInvalidFrame
	}
}

func (s *Session) handleOpen(frame Frame) error {
	stream := newStream(frame.StreamID, s)

	s.streamMu.Lock()

	if _, exists := s.streams[frame.StreamID]; exists {
		s.streamMu.Unlock()
		return ErrInvalidFrame
	}

	s.streams[frame.StreamID] = stream
	s.streamMu.Unlock()

	select {
	case s.acceptCh <- stream:
		return nil

	case <-s.closeCh:
		return ErrSessionClosed
	}
}

func (s *Session) handleData(frame Frame) error {
	stream := s.getStream(frame.StreamID)
	if stream == nil {
		// 对方可能在 CLOSE 后还有残留 DATA，MVP 阶段直接忽略
		return nil
	}

	return stream.pushData(frame.Payload)
}

func (s *Session) handleClose(frame Frame) error {
	stream := s.getStream(frame.StreamID)
	if stream == nil {
		return nil
	}

	stream.closeRemote()
	s.removeStream(frame.StreamID)

	return nil
}

func (s *Session) createLocalStream() *Stream {
	s.streamMu.Lock()
	defer s.streamMu.Unlock()

	id := s.nextID
	s.nextID += 2

	stream := newStream(id, s)
	s.streams[id] = stream

	return stream
}

func (s *Session) getStream(id uint32) *Stream {
	s.streamMu.Lock()
	defer s.streamMu.Unlock()

	return s.streams[id]
}

func (s *Session) removeStream(id uint32) {
	s.streamMu.Lock()
	defer s.streamMu.Unlock()

	delete(s.streams, id)
}

func (s *Session) isClosed() bool {
	select {
	case <-s.closeCh:
		return true
	default:
		return false
	}
}
