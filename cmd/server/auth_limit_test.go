package main

import (
	"bufio"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"mygotunnel/internal/authlimit"
	"mygotunnel/internal/tunnel"
)

func TestTokenAuthenticationChecksBlockAfterCredentialComparison(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	client.SetDeadline(time.Now().Add(time.Second))
	limiter := authlimit.New(8, 1, time.Minute, time.Minute)
	comparisonStarted, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(resume) }) }
	defer release()
	done := make(chan error, 1)
	go func() {
		done <- checkAuthTokenProvider(server, bufio.NewReader(server), func() []string { close(comparisonStarted); <-resume; return []string{"correct"} }, limiter, "peer")
	}()
	if _, err := io.WriteString(client, "AUTH correct\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-comparisonStarted:
	case <-time.After(time.Second):
		t.Fatal("token comparison did not start")
	}
	if err := limiter.Authenticate("peer", false); !errors.Is(err, authlimit.ErrRejected) {
		t.Fatal(err)
	}
	release()
	reply, err := tunnel.ReadLine(bufio.NewReader(client))
	if err != nil || reply != "ERR" {
		t.Fatalf("reply=%q error=%v", reply, err)
	}
	if err := <-done; !errors.Is(err, authlimit.ErrLimited) {
		t.Fatalf("in-flight token authentication bypassed block: %v", err)
	}
	if limiter.Allow("peer") {
		t.Fatal("in-flight token authentication cleared block")
	}
}

func TestInvalidAndTruncatedTokenRequestsDoNotCountCredentialFailures(t *testing.T) {
	for _, request := range []string{"HELLO token\n", "AUTH\n", "AUTH trunca"} {
		t.Run(request, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			limiter := authlimit.New(8, 1, time.Minute, time.Minute)
			done := make(chan error, 1)
			go func() { done <- checkAuthTokens(server, bufio.NewReader(server), []string{"correct"}, limiter, "peer") }()
			if _, err := io.WriteString(client, request); err != nil {
				t.Fatal(err)
			}
			if request[len(request)-1] != '\n' {
				client.Close()
			} else {
				reply, err := tunnel.ReadLine(bufio.NewReader(client))
				if err != nil || reply != "ERR" {
					t.Fatalf("reply=%q error=%v", reply, err)
				}
			}
			if err := <-done; err == nil {
				t.Fatal("invalid authentication request accepted")
			}
			if err := limiter.Authenticate("peer", true); err != nil {
				t.Fatalf("invalid request counted as credential mismatch: %v", err)
			}
		})
	}
}
