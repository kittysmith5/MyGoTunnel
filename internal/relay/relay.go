package relay

import (
	"io"
	"net"
)

// sha?
type closeWriter interface {
	CloseWrite() error
}

func closeWrite(conn net.Conn) {
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func CopyBidirectional(a net.Conn, aReader io.Reader, b net.Conn, bReader io.Reader) {
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
}
