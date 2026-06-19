package tunnel

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

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

func SendOK(conn net.Conn) error {
	_, err := conn.Write([]byte("OK\n"))
	return err
}

func SendERR(conn net.Conn) error {
	_, err := conn.Write([]byte("ERR\n"))
	return err
}
