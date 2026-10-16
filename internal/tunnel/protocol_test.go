package tunnel

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestReadLineLimitsAndBufferedPayload(t *testing.T) {
	tests := []struct {
		name, input, want string
		wantErr, tooLong  bool
	}{
		{"OK", "OK\n", "OK", false, false},
		{"CRLF", "OK\r\n", "OK", false, false},
		{"exact limit", strings.Repeat("x", MaxControlLineBytes-1) + "\n", strings.Repeat("x", MaxControlLineBytes-1), false, false},
		{"over limit", strings.Repeat("x", MaxControlLineBytes) + "\n", "", true, true},
		{"no newline at limit", strings.Repeat("x", MaxControlLineBytes), "", true, true},
		{"unterminated", "OK", "", true, false},
		{"embedded CR", "AUTH bad\rvalue\n", "", true, false},
		{"embedded NUL", "CONNECT bad\x00host:80\n", "", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, size := range []int{16, 4096} {
				got, err := ReadLine(bufio.NewReaderSize(strings.NewReader(tt.input), size))
				if (err != nil) != tt.wantErr || got != tt.want {
					t.Fatalf("size %d: got %q, %v; want %q, error %v", size, got, err, tt.want, tt.wantErr)
				}
				if tt.tooLong && !errors.Is(err, ErrControlLineTooLong) {
					t.Fatalf("got %v, want length error", err)
				}
			}
		})
	}
	reader := bufio.NewReader(strings.NewReader("OK\npayload\x00\n"))
	if _, err := ReadLine(reader); err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(reader)
	if err != nil || string(payload) != "payload\x00\n" {
		t.Fatalf("payload = %q, %v", payload, err)
	}
}

func TestSendCommandRejectsInvalidValuesBeforeWriting(t *testing.T) {
	for _, value := range []string{"", "secret\nCONNECT host:80", "bad\rvalue", "bad\x00value", strings.Repeat("x", MaxControlLineBytes)} {
		if err := SendAuth(nil, value); err == nil {
			t.Fatal("invalid AUTH accepted")
		}
		if err := SendConnect(nil, value); err == nil {
			t.Fatal("invalid CONNECT accepted")
		}
	}
}

func TestSendCommands(t *testing.T) {
	tests := []struct {
		name, want string
		send       func(net.Conn) error
	}{
		{"AUTH", "AUTH token\n", func(c net.Conn) error { return SendAuth(c, "token") }},
		{"CONNECT", "CONNECT example.com:443\n", func(c net.Conn) error { return SendConnect(c, "example.com:443") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			a.SetDeadline(time.Now().Add(time.Second))
			b.SetDeadline(time.Now().Add(time.Second))
			done := make(chan error, 1)
			go func() { done <- tt.send(a) }()
			line, err := bufio.NewReader(b).ReadString('\n')
			if err != nil || line != tt.want {
				t.Fatalf("line = %q, %v", line, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReadLineReturnsTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	_, err := ReadLine(bufio.NewReader(a))
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("got %v, want timeout", err)
	}
}

func TestReadLineDistinguishesBoundaryAndTruncatedEOF(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  error
	}{{"", io.EOF}, {"ACK", io.ErrUnexpectedEOF}, {"ERR DNS", io.ErrUnexpectedEOF}} {
		_, err := ReadLine(bufio.NewReader(strings.NewReader(tc.input)))
		if !errors.Is(err, tc.want) {
			t.Fatalf("ReadLine(%q) = %v, want %v", tc.input, err, tc.want)
		}
	}
}

type setupWriter struct {
	net.Conn
	bytes.Buffer
	writes int
	short  bool
}

func (w *setupWriter) Read(p []byte) (int, error) { return w.Buffer.Read(p) }

func (w *setupWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.short {
		return len(p) - 1, nil
	}
	return w.Buffer.Write(p)
}

// Hide Buffer.WriteString to ensure io.WriteString uses our counted Write.
func (w *setupWriter) WriteString(s string) (int, error) { return w.Write([]byte(s)) }
func TestSendSetupSingleWriteAndValidation(t *testing.T) {
	w := &setupWriter{}
	if err := SendSetup(w, "test-token", "example.test:443"); err != nil {
		t.Fatal(err)
	}
	if w.writes != 1 || w.Buffer.String() != "AUTH test-token\nCONNECT example.test:443\n" {
		t.Fatal("setup was not one ordered write")
	}
	for _, pair := range [][2]string{{"bad\ntoken", "host:443"}, {"token", "bad\nhost"}, {"token", strings.Repeat("x", MaxControlLineBytes)}, {"", "host:443"}} {
		w = &setupWriter{}
		if err := SendSetup(w, pair[0], pair[1]); err == nil || w.writes != 0 {
			t.Fatal("invalid setup was partly written")
		}
	}
	w = &setupWriter{short: true}
	if err := SendSetup(w, "token", "host:443"); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write = %v", err)
	}
}
