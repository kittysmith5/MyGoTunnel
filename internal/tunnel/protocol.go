package tunnel

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

func SendAuth(w io.Writer, token string) error {
	_, err := fmt.Fprintf(w, "AUTH %s\n", token)
	return err
}

func ReadLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(line), nil
}

func SendConnect(w io.Writer, targetAddr string) error {
	_, err := fmt.Fprintf(w, "CONNECT %s\n", targetAddr)
	return err
}

func SendOK(w io.Writer) error {
	_, err := w.Write([]byte("OK\n"))
	return err
}

func SendERR(w io.Writer) error {
	_, err := w.Write([]byte("ERR\n"))
	return err
}
