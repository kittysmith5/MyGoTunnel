package tunnel

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
)

const MaxDatagramSize = 65000

func SendAuth(conn net.Conn, token string) error {
	_, err := fmt.Fprintf(conn, "AUTH %s\n", token)
	return err
}

func ReadLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(line), nil
}

func SendConnect(conn net.Conn, targetAddr string) error {
	_, err := fmt.Fprintf(conn, "CONNECT %s\n", targetAddr)
	return err
}

func SendUDPAssociate(conn net.Conn) error {
	_, err := fmt.Fprint(conn, "UDP\n")
	return err
}

// Datagram frames preserve UDP packet boundaries over the tunnel's TCP stream.
func WriteDatagram(w io.Writer, packet []byte) error {
	if len(packet) == 0 || len(packet) > MaxDatagramSize {
		return fmt.Errorf("invalid UDP datagram size %d", len(packet))
	}
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(packet)))
	if err := writeFull(w, size[:]); err != nil {
		return err
	}
	return writeFull(w, packet)
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func ReadDatagram(r io.Reader) ([]byte, error) {
	var size [2]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n == 0 {
		return nil, fmt.Errorf("invalid UDP datagram size 0")
	}
	packet := make([]byte, n)
	if _, err := io.ReadFull(r, packet); err != nil {
		return nil, err
	}
	return packet, nil
}

func SendOK(conn net.Conn) error {
	_, err := conn.Write([]byte("OK\n"))
	return err
}

func SendERR(conn net.Conn) error {
	_, err := conn.Write([]byte("ERR\n"))
	return err
}
