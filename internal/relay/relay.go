package relay

import (
	"io"
	"sync"
)

const copyBufferSize = 64 * 1024

var copyBufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, copyBufferSize)
		return &buf
	},
}

type closeWriter interface {
	CloseWrite() error
}

func closeWrite(w io.Closer) {
	if cw, ok := w.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}

	_ = w.Close()
}

func CopyBidirectional(a io.WriteCloser, aReader io.Reader, b io.WriteCloser, bReader io.Reader) {
	errCh := make(chan error, 2)

	go func() {
		_, err := copyWithBuffer(b, aReader)
		closeWrite(b)
		errCh <- err
	}()

	go func() {
		_, err := copyWithBuffer(a, bReader)
		closeWrite(a)
		errCh <- err
	}()

	<-errCh
}

func copyWithBuffer(dst io.Writer, src io.Reader) (int64, error) {
	bufPtr := copyBufferPool.Get().(*[]byte)
	defer copyBufferPool.Put(bufPtr)

	return io.CopyBuffer(dst, src, *bufPtr)
}
