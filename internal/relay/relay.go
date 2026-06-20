package relay

import (
	"io"
)

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
		_, err := io.Copy(b, aReader)
		closeWrite(b)
		errCh <- err
	}()

	go func() {
		_, err := io.Copy(a, bReader)
		closeWrite(a)
		errCh <- err
	}()

	<-errCh
	<-errCh
}
