package main

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
)

func TestCheckAuth(t *testing.T) {
	tests := []struct {
		name          string
		request       string
		wantResponse  string
		wantErr       bool
		wantErrText   string
		secretNotSeen string
	}{
		{
			name:         "valid token",
			request:      "AUTH expected-token\n",
			wantResponse: "OK\n",
		},
		{
			name:          "wrong token",
			request:       "AUTH secret-value\n",
			wantResponse:  "ERR\n",
			wantErr:       true,
			wantErrText:   "authentication token mismatch",
			secretNotSeen: "secret-value",
		},
		{
			name:         "invalid command",
			request:      "CONNECT example.com:443\n",
			wantResponse: "ERR\n",
			wantErr:      true,
			wantErrText:  "invalid authentication command",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()
			defer clientConn.Close()

			errCh := make(chan error, 1)
			go func() {
				errCh <- checkAuth(serverConn, bufio.NewReader(serverConn), "expected-token")
			}()

			if _, err := io.WriteString(clientConn, tt.request); err != nil {
				t.Fatalf("write authentication request: %v", err)
			}

			response := make([]byte, len(tt.wantResponse))
			if _, err := io.ReadFull(clientConn, response); err != nil {
				t.Fatalf("read authentication response: %v", err)
			}

			err := <-errCh
			if (err != nil) != tt.wantErr {
				t.Fatalf("checkAuth() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got := string(response); got != tt.wantResponse {
				t.Errorf("response = %q, want %q", got, tt.wantResponse)
			}
			if tt.wantErrText != "" && !strings.Contains(err.Error(), tt.wantErrText) {
				t.Errorf("checkAuth() error = %q, want it to contain %q", err, tt.wantErrText)
			}
			if tt.secretNotSeen != "" && strings.Contains(err.Error(), tt.secretNotSeen) {
				t.Errorf("checkAuth() error exposes authentication token: %q", err)
			}
		})
	}
}
