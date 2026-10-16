package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"mygotunnel/internal/config"
	"mygotunnel/internal/relay"
	"mygotunnel/internal/tunnel"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestTransientRouteResetThenRecovery runs a real SOCKS client, uTLS tunnel,
// TLS server and echo target. The first transport connection is reset before
// TLS; the next new request must recover without restarting either process.
func TestTransientRouteResetThenRecovery(t *testing.T) {
	configPath := t.TempDir() + "/server.json"
	code, err := config.InitializeServer(configPath, "localhost:9001", ":9001")
	if err != nil {
		t.Fatal(err)
	}
	serverCfg, err := config.LoadServerConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg, err := config.DecodeConnection(code)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.LoadX509KeyPair(serverCfg.CertFile, serverCfg.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	var targetWG sync.WaitGroup
	targetWG.Add(1)
	go func() {
		defer targetWG.Done()
		for {
			c, e := target.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	server, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	var serverWG sync.WaitGroup
	serverWG.Add(1)
	go func() {
		defer serverWG.Done()
		for {
			c, e := server.Accept()
			if e != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				a, e := tunnel.ReadLine(r)
				if e != nil || a != "AUTH "+serverCfg.AuthToken {
					return
				}
				if tunnel.SendOK(c) != nil {
					return
				}
				line, e := tunnel.ReadLine(r)
				if e != nil || line != "CONNECT "+target.Addr().String() {
					return
				}
				if tunnel.SendOK(c) != nil {
					return
				}
				targetConn, e := net.DialTimeout("tcp", target.Addr().String(), time.Second)
				if e != nil {
					return
				}
				defer targetConn.Close()
				_ = relay.CopyBidirectional(c, r, targetConn, targetConn)
			}(c)
		}
	}()
	var accepted atomic.Int32
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	var proxyWG sync.WaitGroup
	proxyWG.Add(1)
	go func() {
		defer proxyWG.Done()
		for {
			front, e := proxy.Accept()
			if e != nil {
				return
			}
			n := accepted.Add(1)
			if n == 1 {
				front.Close()
				continue
			}
			back, e := net.DialTimeout("tcp", server.Addr().String(), time.Second)
			if e != nil {
				front.Close()
				continue
			}
			go func() {
				defer front.Close()
				defer back.Close()
				var timer *time.Timer
				if n == 2 {
					timer = time.AfterFunc(200*time.Millisecond, func() { front.Close(); back.Close() })
					defer timer.Stop()
				}
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(back, front); done <- struct{}{} }()
				go func() { _, _ = io.Copy(front, back); done <- struct{}{} }()
				<-done
			}()
		}
	}()
	clientCfg.RemoteAddr = proxy.Addr().String()
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()
	var handlers sync.WaitGroup
	go func() {
		for {
			c, e := front.Accept()
			if e != nil {
				return
			}
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				handleClient(c, clientCfg, slog.New(slog.NewTextHandler(io.Discard, nil)), func() {})
			}()
		}
	}()
	request := func() (net.Conn, byte, error) {
		c, e := net.DialTimeout("tcp", front.Addr().String(), time.Second)
		if e != nil {
			return nil, 0, e
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, e = c.Write([]byte{5, 1, 0}); e != nil {
			c.Close()
			return nil, 0, e
		}
		m := make([]byte, 2)
		if _, e = io.ReadFull(c, m); e != nil {
			c.Close()
			return nil, 0, e
		}
		if m[1] != 0 {
			c.Close()
			return nil, 0, fmt.Errorf("unexpected method %d", m[1])
		}
		ip := target.Addr().(*net.TCPAddr).IP.To4()
		port := target.Addr().(*net.TCPAddr).Port
		req := []byte{5, 1, 0, 1}
		req = append(req, ip...)
		req = append(req, byte(port>>8), byte(port))
		if _, e = c.Write(req); e != nil {
			c.Close()
			return nil, 0, e
		}
		reply := make([]byte, 10)
		if _, e = io.ReadFull(c, reply); e != nil {
			c.Close()
			return nil, 0, e
		}
		return c, reply[1], nil
	}
	started := time.Now()
	c, rep, e := request()
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if rep == 0 {
		t.Fatal("expected first request to fail during injected reset")
	}
	c, rep, e = request()
	if e != nil {
		t.Fatal(e)
	}
	if rep != 0 {
		t.Fatalf("request did not recover after route restored: REP=%d", rep)
	}
	time.Sleep(250 * time.Millisecond) // injected established-stream reset
	const payload = "recovered-after-route-reset"
	_, _ = c.Write([]byte(payload))
	got := make([]byte, len(payload))
	if _, e = io.ReadFull(c, got); e == nil {
		t.Fatal("injected active tunnel reset was not observed")
	}
	c.Close()
	c, rep, e = request()
	if e != nil || rep != 0 {
		t.Fatalf("new request after established reset: REP=%d error=%v", rep, e)
	}
	if _, e = c.Write([]byte(payload)); e != nil {
		t.Fatal(e)
	}
	got = make([]byte, len(payload))
	if _, e = io.ReadFull(c, got); e != nil || string(got) != payload {
		t.Fatalf("recovered payload=%q error=%v", got, e)
	}
	c.Close()
	if accepted.Load() != 3 {
		t.Fatalf("route attempts=%d, want 3", accepted.Load())
	}
	if time.Since(started) > 3*time.Second {
		t.Fatalf("recovery took %v", time.Since(started))
	}
	front.Close()
	proxy.Close()
	server.Close()
	handlers.Wait()
	proxyWG.Wait()
	serverWG.Wait()
	target.Close()
	targetWG.Wait()
}
