package tunnel

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

// MaxControlLineBytes includes the terminating newline.
const MaxControlLineBytes = 4096

// ControlTimeout bounds AUTH/CONNECT reads and writes, not application traffic.
const ControlTimeout = 20 * time.Second

// ControlReplyTimeout is a separate, bounded budget for the final OK/ERR.
const ControlReplyTimeout = time.Second

// PreparedAckTimeout bounds command delivery and the immediate receipt ACK,
// independently of the time needed to resolve and connect to the target.
const PreparedAckTimeout = 2 * time.Second

const PreparedAckReady = "READY ACK"
const CommandAcknowledged = "ACK"

// Prepared connections are authenticated, bounded and expire without heartbeats.
const PreparedIdleTimeout = 60 * time.Second

var ErrAuthRejected = errors.New("auth rejected")
var ErrConnectRejected = errors.New("connect rejected")

var ErrControlLineTooLong = errors.New("control line exceeds 4096 bytes")

func SendAuth(conn net.Conn, token string) error {
	return sendCommand(conn, "AUTH", token)
}

// ReadLine limits allocation independently of the reader's buffer size and
// leaves any prefetched application payload in the same reader.
func ReadLine(reader *bufio.Reader) (string, error) {
	var line []byte
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(fragment) > MaxControlLineBytes-len(line) {
			return "", ErrControlLineTooLong
		}
		line = append(line, fragment...)
		if err == nil {
			text := strings.TrimSuffix(string(line[:len(line)-1]), "\r")
			if containsControl(text) {
				return "", errors.New("invalid control character in control line")
			}
			return strings.TrimSpace(text), nil
		}
		if len(line) == MaxControlLineBytes {
			return "", ErrControlLineTooLong
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			if errors.Is(err, io.EOF) && len(line) > 0 {
				return "", io.ErrUnexpectedEOF
			}
			return "", err
		}
	}
}

func SendConnect(conn net.Conn, targetAddr string) error {
	return sendCommand(conn, "CONNECT", targetAddr)
}

// SendSetup pipelines both commands in one write, preserving AUTH then CONNECT.
// Validate both lines before writing anything, including when the target is invalid.
func SendSetup(conn net.Conn, token, targetAddr string) error {
	if err := validateCommand("AUTH", token); err != nil {
		return err
	}
	if err := validateCommand("CONNECT", targetAddr); err != nil {
		return err
	}
	return writeControl(conn, "AUTH "+token+"\nCONNECT "+targetAddr+"\n")
}

func sendCommand(conn net.Conn, command, value string) error {
	if err := validateCommand(command, value); err != nil {
		return err
	}
	return writeControl(conn, command+" "+value+"\n")
}

func validateCommand(command, value string) error {
	if value == "" || containsControl(value) {
		return errors.New("invalid control command value")
	}
	if len(value) > MaxControlLineBytes-len(command)-2 {
		return ErrControlLineTooLong
	}
	return nil
}

func writeControl(conn net.Conn, data string) error {
	n, err := io.WriteString(conn, data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

func containsControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func SendOK(conn net.Conn) error {
	_, err := conn.Write([]byte("OK\n"))
	return err
}

func SendERR(conn net.Conn) error {
	_, err := conn.Write([]byte("ERR\n"))
	return err
}

// SendPrepare negotiates preconnection support after ordinary AUTH.
func SendPrepare(conn net.Conn, token string) error {
	return sendPrepare(conn, token, false)
}

func SendPrepareWithAck(conn net.Conn, token string) error {
	return sendPrepare(conn, token, true)
}

func sendPrepare(conn net.Conn, token string, ack bool) error {
	if err := validateCommand("AUTH", token); err != nil {
		return err
	}
	if ack {
		return writeControl(conn, "AUTH "+token+"\nPREPARE ACK\n")
	}
	return writeControl(conn, "AUTH "+token+"\nPREPARE\n")
}
func SendReady(conn net.Conn) error { return writeControl(conn, "READY\n") }
func SendBusy(conn net.Conn) error  { return writeControl(conn, "BUSY\n") }

func SendReadyWithAck(conn net.Conn) error { return writeControl(conn, PreparedAckReady+"\n") }
func SendAcknowledged(conn net.Conn) error { return writeControl(conn, CommandAcknowledged+"\n") }
