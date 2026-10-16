package preconnect

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/tunnel"
)

type prepareACKServer struct {
	listener net.Listener
	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	commands []string
	errors   []error
	wg       sync.WaitGroup
	done     chan struct{}
}

func newPrepareACKServer(t *testing.T, respond func(int, string, net.Conn, *bufio.Reader) error) (*prepareACKServer, *config.ClientConfig) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.json")
	code, err := config.InitializeServer(path, "localhost:9001", ":9001")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.DecodeConnection(code)
	if err != nil {
		t.Fatal(err)
	}
	serverCfg, err := config.LoadServerConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.LoadX509KeyPair(serverCfg.CertFile, serverCfg.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg.RemoteAddr = listener.Addr().String()
	server := &prepareACKServer{listener: listener, conns: make(map[net.Conn]struct{}), done: make(chan struct{})}
	go func() {
		defer close(server.done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			server.mu.Lock()
			server.conns[conn] = struct{}{}
			server.mu.Unlock()
			server.wg.Add(1)
			go func() {
				defer server.wg.Done()
				defer conn.Close()
				defer func() {
					server.mu.Lock()
					delete(server.conns, conn)
					server.mu.Unlock()
				}()
				err := conn.SetDeadline(time.Now().Add(4 * time.Second))
				reader := bufio.NewReader(conn)
				var auth, command string
				if err == nil {
					auth, err = tunnel.ReadLine(reader)
				}
				if err == nil && auth != "AUTH "+cfg.AuthToken {
					err = errors.New("unexpected authentication command")
				}
				if err == nil {
					command, err = tunnel.ReadLine(reader)
				}
				if err == nil {
					server.mu.Lock()
					index := len(server.commands)
					server.commands = append(server.commands, command)
					server.mu.Unlock()
					err = respond(index, command, conn, reader)
				}
				if err != nil {
					server.mu.Lock()
					server.errors = append(server.errors, err)
					server.mu.Unlock()
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-server.done
		server.mu.Lock()
		for conn := range server.conns {
			_ = conn.(*tls.Conn).NetConn().Close()
		}
		server.mu.Unlock()
		server.wg.Wait()
		for _, err := range server.errors {
			t.Error("test TLS server:", err)
		}
	})
	return server, cfg
}

func (s *prepareACKServer) checkCommands(t *testing.T, want ...string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !reflect.DeepEqual(s.commands, want) {
		t.Fatalf("prepare commands = %q, want %q", s.commands, want)
	}
}

func TestPrepareACKNegotiationPreservesBufferedDataAndConnection(t *testing.T) {
	const payload = "binary\x00\nreply"
	server, cfg := newPrepareACKServer(t, func(_ int, command string, conn net.Conn, reader *bufio.Reader) error {
		if command != "PREPARE ACK" {
			return fmt.Errorf("unexpected prepare command %q", command)
		}
		if _, err := io.WriteString(conn, "OK\nREADY ACK\nACK\nOK\n"+payload); err != nil {
			return err
		}
		line, err := tunnel.ReadLine(reader)
		if err != nil {
			return err
		}
		if line != "PING" {
			return fmt.Errorf("unexpected post-prepare command %q", line)
		}
		_, err = io.WriteString(conn, "PONG\n")
		return err
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	entry, err := NewPreparer(cfg)(ctx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer entry.Conn.Close()
	if !entry.CommandACK {
		t.Fatal("negotiated READY ACK did not enable command acknowledgment")
	}
	if entry.Reader.Buffered() == 0 {
		t.Fatal("coalesced response was not retained in the prepared reader")
	}
	for _, want := range []string{"ACK", "OK"} {
		if line, err := tunnel.ReadLine(entry.Reader); err != nil || line != want {
			t.Fatalf("buffered response = %q, %v, want %q", line, err, want)
		}
	}
	data := make([]byte, len(payload))
	if _, err := io.ReadFull(entry.Reader, data); err != nil || string(data) != payload {
		t.Fatalf("buffered payload = %q, %v", data, err)
	}
	// Canceling the completed preparation must not close its transferred socket.
	if _, err := io.WriteString(entry.Conn, "PING\n"); err != nil {
		t.Fatal("completed preparation retained context ownership:", err)
	}
	if line, err := tunnel.ReadLine(entry.Reader); err != nil || line != "PONG" {
		t.Fatalf("post-prepare response = %q, %v", line, err)
	}
	server.checkCommands(t, "PREPARE ACK")
}

func TestPrepareLegacyAPIKeepsOriginalProtocol(t *testing.T) {
	server, cfg := newPrepareACKServer(t, func(_ int, _ string, conn net.Conn, _ *bufio.Reader) error {
		_, err := io.WriteString(conn, "OK\nREADY\n")
		return err
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	entry, err := Prepare(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer entry.Conn.Close()
	if entry.CommandACK {
		t.Fatal("legacy Prepare unexpectedly enabled command acknowledgment")
	}
	server.checkCommands(t, "PREPARE")
}

func TestPrepareACKLegacyFallbackCacheIsScopedToFactory(t *testing.T) {
	for _, unsupported := range []string{"eof", "err"} {
		t.Run(unsupported, func(t *testing.T) {
			server, cfg := newPrepareACKServer(t, func(_ int, command string, conn net.Conn, _ *bufio.Reader) error {
				if _, err := io.WriteString(conn, "OK\n"); err != nil {
					return err
				}
				if command == "PREPARE ACK" {
					if unsupported == "err" {
						_, err := io.WriteString(conn, "ERR\n")
						return err
					}
					return nil
				}
				if command != "PREPARE" {
					return fmt.Errorf("unexpected prepare command %q", command)
				}
				_, err := io.WriteString(conn, "READY\n")
				return err
			})
			factory := NewPreparer(cfg)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			for _, prepare := range []Factory{factory, factory, NewPreparer(cfg)} {
				entry, err := prepare(ctx)
				if err != nil {
					t.Fatal(err)
				}
				entry.Conn.Close()
				if entry.CommandACK {
					t.Fatal("legacy READY unexpectedly enabled command acknowledgment")
				}
			}
			server.checkCommands(t, "PREPARE ACK", "PREPARE", "PREPARE", "PREPARE ACK", "PREPARE")
		})
	}
}

func TestPrepareACKFailedLegacyRetryDoesNotCacheCapability(t *testing.T) {
	for _, rejected := range []struct {
		name     string
		response string
		want     error
	}{{"busy", "BUSY\n", ErrBusy}, {"unsupported", "ERR\n", ErrUnsupported}} {
		t.Run(rejected.name, func(t *testing.T) {
			server, cfg := newPrepareACKServer(t, func(index int, _ string, conn net.Conn, _ *bufio.Reader) error {
				response := "OK\n"
				switch index {
				case 0:
					response += "ERR\n"
				case 1:
					response += rejected.response
				default:
					response += "READY ACK\n"
				}
				_, err := io.WriteString(conn, response)
				return err
			})
			factory := NewPreparer(cfg)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if entry, err := factory(ctx); !errors.Is(err, rejected.want) {
				if entry != nil {
					entry.Conn.Close()
				}
				t.Fatalf("legacy retry error = %v, want %v", err, rejected.want)
			}
			entry, err := factory(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer entry.Conn.Close()
			if !entry.CommandACK {
				t.Fatal("failed legacy retry cached unsupported capability")
			}
			server.checkCommands(t, "PREPARE ACK", "PREPARE", "PREPARE ACK")
		})
	}
}

func TestPrepareACKRefusalAndMalformedResponseDoNotRetry(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response string
		want     error
	}{
		{"before_auth_eof", "", io.EOF},
		{"auth_rejected", "ERR\n", tunnel.ErrAuthRejected},
		{"busy", "OK\nBUSY\n", ErrBusy},
		{"unknown", "OK\nWHAT\n", ErrUnsupported},
		{"typed_rejection", "OK\nERR LIMIT\n", ErrUnsupported},
		{"overlong", "OK\n" + strings.Repeat("x", tunnel.MaxControlLineBytes) + "\n", tunnel.ErrControlLineTooLong},
		{"control_character", "OK\nREADY\x00ACK\n", nil},
		{"partial_response_without_newline", "OK\nREADY A", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, cfg := newPrepareACKServer(t, func(index int, _ string, conn net.Conn, _ *bufio.Reader) error {
				response := tc.response
				if index > 0 {
					response = "OK\nREADY ACK\n"
				}
				_, err := io.WriteString(conn, response)
				return err
			})
			factory := NewPreparer(cfg)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if entry, err := factory(ctx); err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				if entry != nil {
					entry.Conn.Close()
				}
				t.Fatalf("negotiation error = %v, want refusal without retry (%v)", err, tc.want)
			}
			server.checkCommands(t, "PREPARE ACK")
			entry, err := factory(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer entry.Conn.Close()
			if !entry.CommandACK {
				t.Fatal("refused/malformed negotiation cached legacy capability")
			}
			server.checkCommands(t, "PREPARE ACK", "PREPARE ACK")
		})
	}
}

func TestPrepareACKTimeoutAndCancellationDoNotRetry(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		name := "timeout"
		if canceled {
			name = "canceled"
		}
		t.Run(name, func(t *testing.T) {
			authenticated := make(chan struct{})
			server, cfg := newPrepareACKServer(t, func(index int, _ string, conn net.Conn, _ *bufio.Reader) error {
				if index > 0 {
					_, err := io.WriteString(conn, "OK\nREADY ACK\n")
					return err
				}
				if _, err := io.WriteString(conn, "OK\n"); err != nil {
					return err
				}
				close(authenticated)
				_, _ = io.Copy(io.Discard, conn)
				return nil
			})
			factory := NewPreparer(cfg)
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			type result struct {
				entry *Entry
				err   error
			}
			done := make(chan result, 1)
			go func() {
				entry, err := factory(ctx)
				done <- result{entry, err}
			}()
			select {
			case <-authenticated:
			case <-ctx.Done():
				t.Fatal("test TLS authentication did not complete before the deadline")
			}
			if canceled {
				cancel()
			}
			var got result
			select {
			case got = <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("preparation ignored canceled/deadline context")
			}
			if got.entry != nil {
				got.entry.Conn.Close()
			}
			if got.err == nil || errors.Is(got.err, ErrUnsupported) {
				t.Fatalf("canceled/deadline preparation error = %v", got.err)
			}
			if canceled && !errors.Is(got.err, context.Canceled) {
				t.Fatalf("canceled preparation error = %v", got.err)
			}
			server.checkCommands(t, "PREPARE ACK")
			retryCtx, retryCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer retryCancel()
			entry, err := factory(retryCtx)
			if err != nil {
				t.Fatal(err)
			}
			defer entry.Conn.Close()
			if !entry.CommandACK {
				t.Fatal("cancellation/timeout cached legacy capability")
			}
			server.checkCommands(t, "PREPARE ACK", "PREPARE ACK")
		})
	}
}

func TestPrepareACKConcurrentLegacyDiscovery(t *testing.T) {
	server, cfg := newPrepareACKServer(t, func(_ int, command string, conn net.Conn, _ *bufio.Reader) error {
		response := "OK\nREADY\n"
		if command == "PREPARE ACK" {
			response = "OK\nERR\n"
		}
		_, err := io.WriteString(conn, response)
		return err
	})
	factory := NewPreparer(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 4)
	for range 4 {
		go func() {
			entry, err := factory(ctx)
			if err == nil {
				entry.Conn.Close()
				if entry.CommandACK {
					err = errors.New("legacy preparation enabled command acknowledgment")
				}
			}
			done <- err
		}()
	}
	for range 4 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	entry, err := factory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer entry.Conn.Close()
	server.mu.Lock()
	defer server.mu.Unlock()
	legacy, probes := 0, 0
	for _, command := range server.commands {
		switch command {
		case "PREPARE":
			legacy++
		case "PREPARE ACK":
			probes++
		default:
			t.Fatal("unexpected prepare command", command)
		}
	}
	if legacy != 5 || probes < 1 || probes > 4 || server.commands[len(server.commands)-1] != "PREPARE" {
		t.Fatalf("legacy/probe counts = %d/%d, commands = %q", legacy, probes, server.commands)
	}
}
