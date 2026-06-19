package relay

import (
	"io"
)

type ReadWriteCloser interface {
	io.Reader
	io.Writer
	io.Closer
}

type closeWriter interface {
	CloseWrite() error
}

func closeWriteOrClose(c io.Closer) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}

	_ = c.Close()
}

func CopyBidirectional(
	a ReadWriteCloser,
	aReader io.Reader,
	b ReadWriteCloser,
	bReader io.Reader,
) {
	errCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(b, aReader)
		closeWriteOrClose(b)
		errCh <- err
	}()

	go func() {
		_, err := io.Copy(a, bReader)
		closeWriteOrClose(a)
		errCh <- err
	}()

	<-errCh
}
