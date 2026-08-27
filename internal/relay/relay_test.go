package relay

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestCopyBidirectionalDrainsReverseDataAfterHalfClose(t *testing.T) {
	aRelay, aPeer := newTCPPair(t)
	bRelay, bPeer := newTCPPair(t)
	setTestDeadlines(t, aRelay, aPeer, bRelay, bPeer)

	resultCh := startRelay(aRelay, aRelay, bRelay, bRelay)

	const request = "request body"
	if _, err := io.WriteString(aPeer, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if err := aPeer.CloseWrite(); err != nil {
		t.Fatalf("half-close request: %v", err)
	}

	gotRequest, err := io.ReadAll(bPeer)
	if err != nil {
		t.Fatalf("read request: %v", err)
	}
	if got := string(gotRequest); got != request {
		t.Fatalf("request = %q, want %q", got, request)
	}

	const response = "response after request EOF"
	if _, err := io.WriteString(bPeer, response); err != nil {
		t.Fatalf("write response: %v", err)
	}
	if err := bPeer.CloseWrite(); err != nil {
		t.Fatalf("half-close response: %v", err)
	}

	gotResponse, err := io.ReadAll(aPeer)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if got := string(gotResponse); got != response {
		t.Fatalf("response = %q, want %q", got, response)
	}

	result := waitForResult(t, resultCh)
	if result.Err != nil {
		t.Fatalf("CopyBidirectional() error = %v", result.Err)
	}
	if result.AToB.Bytes != int64(len(request)) {
		t.Errorf("A-to-B bytes = %d, want %d", result.AToB.Bytes, len(request))
	}
	if result.BToA.Bytes != int64(len(response)) {
		t.Errorf("B-to-A bytes = %d, want %d", result.BToA.Bytes, len(response))
	}
}

func TestCopyBidirectionalPreservesBufferedReverseData(t *testing.T) {
	aRelay, aPeer := newTCPPair(t)
	bRelay, bPeer := newTCPPair(t)
	setTestDeadlines(t, aRelay, aPeer, bRelay, bPeer)

	const response = "already buffered response"
	if _, err := io.WriteString(bPeer, response); err != nil {
		t.Fatalf("write response: %v", err)
	}
	if err := bPeer.CloseWrite(); err != nil {
		t.Fatalf("half-close response: %v", err)
	}

	bufferedReader := bufio.NewReader(bRelay)
	if _, err := bufferedReader.Peek(len(response)); err != nil {
		t.Fatalf("buffer response: %v", err)
	}

	resultCh := startRelay(aRelay, aRelay, bRelay, bufferedReader)

	const request = "request"
	if _, err := io.WriteString(aPeer, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if err := aPeer.CloseWrite(); err != nil {
		t.Fatalf("half-close request: %v", err)
	}

	gotResponse, err := io.ReadAll(aPeer)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if got := string(gotResponse); got != response {
		t.Fatalf("response = %q, want %q", got, response)
	}

	gotRequest, err := io.ReadAll(bPeer)
	if err != nil {
		t.Fatalf("read request: %v", err)
	}
	if got := string(gotRequest); got != request {
		t.Fatalf("request = %q, want %q", got, request)
	}

	result := waitForResult(t, resultCh)
	if result.Err != nil {
		t.Fatalf("CopyBidirectional() error = %v", result.Err)
	}
}

func TestCopyBidirectionalInterruptsOtherDirectionAfterError(t *testing.T) {
	aRelay, aPeer := newTCPPair(t)
	bRelay, bPeer := newTCPPair(t)
	setTestDeadlines(t, aRelay, aPeer, bRelay, bPeer)

	wantErr := errors.New("source failed")
	resultCh := startRelay(aRelay, errorReader{err: wantErr}, bRelay, bRelay)

	result := waitForResult(t, resultCh)
	if !errors.Is(result.Err, wantErr) {
		t.Fatalf("CopyBidirectional() error = %v, want %v", result.Err, wantErr)
	}
	if !errors.Is(result.AToB.Err, wantErr) {
		t.Errorf("A-to-B error = %v, want %v", result.AToB.Err, wantErr)
	}
	if result.BToA.Err == nil {
		t.Error("B-to-A error = nil, want interruption error")
	}
}

func TestCopyBidirectionalRejectsConnectionWithoutHalfClose(t *testing.T) {
	aRelay, aPeer := newTCPPair(t)
	bRelay, bPeer := newTCPPair(t)
	setTestDeadlines(t, aRelay, aPeer, bRelay, bPeer)

	resultCh := startRelay(aRelay, strings.NewReader(""), connWithoutCloseWrite{Conn: bRelay}, bRelay)
	result := waitForResult(t, resultCh)

	if !errors.Is(result.Err, ErrHalfCloseUnsupported) {
		t.Fatalf("CopyBidirectional() error = %v, want ErrHalfCloseUnsupported", result.Err)
	}
}

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}

type connWithoutCloseWrite struct {
	net.Conn
}

func newTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	acceptCh := make(chan struct {
		conn *net.TCPConn
		err  error
	}, 1)
	go func() {
		conn, acceptErr := listener.AcceptTCP()
		acceptCh <- struct {
			conn *net.TCPConn
			err  error
		}{conn: conn, err: acceptErr}
	}()

	peer, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		listener.Close()
		t.Fatalf("dial: %v", err)
	}

	accepted := <-acceptCh
	if err := listener.Close(); err != nil {
		peer.Close()
		t.Fatalf("close listener: %v", err)
	}
	if accepted.err != nil {
		peer.Close()
		t.Fatalf("accept: %v", accepted.err)
	}

	t.Cleanup(func() {
		accepted.conn.Close()
		peer.Close()
	})

	return accepted.conn, peer
}

func setTestDeadlines(t *testing.T, conns ...net.Conn) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for _, conn := range conns {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
	}
}

func startRelay(a net.Conn, aReader io.Reader, b net.Conn, bReader io.Reader) <-chan Result {
	resultCh := make(chan Result, 1)
	go func() {
		result := CopyBidirectional(a, aReader, b, bReader)
		a.Close()
		b.Close()
		resultCh <- result
	}()

	return resultCh
}

func waitForResult(t *testing.T, resultCh <-chan Result) Result {
	t.Helper()

	select {
	case result := <-resultCh:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("CopyBidirectional() did not return")
		return Result{}
	}
}
