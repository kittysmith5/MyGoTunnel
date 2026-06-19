package mux

import (
	"io"
	"net"
	"testing"
)

func TestMuxSingleStream(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	clientSess := NewSession(c1, ModeClient)
	serverSess := NewSession(c2, ModeServer)

	clientStream, err := clientSess.OpenStream()
	if err != nil {
		t.Fatal(err)
	}

	serverStream, err := serverSess.AcceptStream()
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("hello mux")

	go func() {
		_, _ = clientStream.Write(msg)
	}()

	buf := make([]byte, 1024)
	n, err := serverStream.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}

	if string(buf[:n]) != string(msg) {
		t.Fatalf("want %q, got %q", string(msg), string(buf[:n]))
	}
}
