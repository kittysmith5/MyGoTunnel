package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/logging"
	"mygotunnel/internal/relay"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
	"mygotunnel/internal/utlsconn"
)

func main() {
	configPath := flag.String("config", "configs/client.json", "config file path")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, or error")
	logFormat := flag.String("log-format", logging.FormatText, "log format: text or json")
	flag.Parse()

	logger, err := logging.New(os.Stderr, logging.Options{
		Component: "client",
		Level:     *logLevel,
		Format:    *logFormat,
	})
	if err != nil {
		slog.Error("invalid logging configuration", "component", "client", "error", err)
		os.Exit(2)
	}

	if err := run(*configPath, logger); err != nil {
		logger.Error("client stopped", "error", err)
		os.Exit(1)
	}
}

func run(configPath string, logger *slog.Logger) error {
	cfg, err := config.LoadClientConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ln, err := net.Listen("tcp", cfg.LocalAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.LocalAddr, err)
	}
	defer ln.Close()

	logger.Info("SOCKS5 listener started",
		"listen_addr", cfg.LocalAddr,
		"remote_addr", cfg.RemoteAddr,
		"sni", cfg.SNI,
	)

	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.Error("accept connection failed", "error", err)
			continue
		}

		go handleClient(conn, cfg, logger)
	}
}

func handleClient(clientConn net.Conn, cfg *config.ClientConfig, logger *slog.Logger) {
	defer clientConn.Close()

	clientAddr := clientConn.RemoteAddr().String()
	connectionLogger := logger.With("client_addr", clientAddr)
	startedAt := time.Now()
	connectionLogger.Debug("connection accepted")
	defer func() {
		connectionLogger.Debug("connection closed", "duration", time.Since(startedAt))
	}()

	username, password, requireSOCKSAuth := cfg.SOCKSCredentials()
	if err := socks5.HandshakeWithCredentials(clientConn, username, password, requireSOCKSAuth); err != nil {
		connectionLogger.Warn("SOCKS5 handshake failed", "error", err)
		return
	}

	request, err := socks5.ReadRequestDetails(clientConn)
	if err != nil {
		connectionLogger.Warn("SOCKS5 request failed", "error", err)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}
	if request.Command == socks5.CommandUDPAssociate {
		handleUDPAssociate(clientConn, request, cfg, connectionLogger, startedAt)
		return
	}
	targetAddr := net.JoinHostPort(request.Address, fmt.Sprint(request.Port))

	requestLogger := connectionLogger.With("target_addr", targetAddr)
	requestLogger.Debug("SOCKS5 CONNECT received")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	remoteConn, err := utlsconn.Dial(ctx, cfg.RemoteAddr, cfg.SNI)
	cancel()
	if err != nil {
		requestLogger.Warn("dial remote uTLS server failed",
			"remote_addr", cfg.RemoteAddr,
			"error", err,
		)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}
	defer remoteConn.Close()

	remoteReader := bufio.NewReader(remoteConn)

	if err := tunnel.SendAuth(remoteConn, cfg.AuthToken); err != nil {
		requestLogger.Warn("send authentication request failed", "error", err)
		return
	}

	authResp, err := tunnel.ReadLine(remoteReader)
	if err != nil {
		requestLogger.Warn("read authentication response failed", "error", err)
		return
	}

	if authResp != "OK" {
		requestLogger.Warn("remote authentication rejected")
		return
	}

	if err := tunnel.SendConnect(remoteConn, targetAddr); err != nil {
		requestLogger.Warn("send CONNECT request failed", "error", err)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}

	resp, err := tunnel.ReadLine(remoteReader)
	if err != nil {
		requestLogger.Warn("read CONNECT response failed", "error", err)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}

	if resp != "OK" {
		requestLogger.Warn("remote CONNECT rejected")
		_ = socks5.Reply(clientConn, 0x05)
		return
	}

	if err := socks5.Reply(clientConn, 0x00); err != nil {
		requestLogger.Warn("send SOCKS5 success reply failed", "error", err)
		return
	}

	requestLogger.Info("tunnel established", "remote_addr", cfg.RemoteAddr)
	result := relay.CopyBidirectional(clientConn, clientConn, remoteConn, remoteReader)
	logging.LogTunnelResult(requestLogger, result, startedAt)
}

func handleUDPAssociate(clientConn net.Conn, request socks5.Request, cfg *config.ClientConfig, logger *slog.Logger, startedAt time.Time) {
	const udpFrameQueueSize = 256
	bindIP := net.IPv4zero
	if tcpLocal, ok := clientConn.LocalAddr().(*net.TCPAddr); ok && tcpLocal.IP.To4() == nil {
		bindIP = net.IPv6unspecified
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindIP})
	if err != nil {
		logger.Warn("bind SOCKS5 UDP relay failed", "error", err)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}
	defer udpConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	remoteConn, err := utlsconn.Dial(ctx, cfg.RemoteAddr, cfg.SNI)
	cancel()
	if err != nil {
		logger.Warn("dial remote uTLS server failed", "remote_addr", cfg.RemoteAddr, "error", err)
		return
	}
	defer remoteConn.Close()
	reader := bufio.NewReader(remoteConn)
	if err := tunnel.SendAuth(remoteConn, cfg.AuthToken); err != nil {
		logger.Warn("send authentication request failed", "error", err)
		return
	}
	response, err := tunnel.ReadLine(reader)
	if err != nil || response != "OK" {
		logger.Warn("remote authentication failed", "error", err)
		return
	}
	if err := tunnel.SendUDPAssociate(remoteConn); err != nil {
		logger.Warn("send UDP ASSOCIATE request failed", "error", err)
		return
	}
	response, err = tunnel.ReadLine(reader)
	if err != nil || response != "OK" {
		logger.Warn("remote UDP ASSOCIATE failed", "error", err)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}
	bound := *udpConn.LocalAddr().(*net.UDPAddr)
	if tcpLocal, ok := clientConn.LocalAddr().(*net.TCPAddr); ok {
		bound.IP = tcpLocal.IP
	}
	if bound.IP == nil || bound.IP.IsUnspecified() {
		bound.IP = net.IPv4(127, 0, 0, 1)
	}
	if err := socks5.ReplyBound(clientConn, 0x00, &bound); err != nil {
		logger.Warn("send UDP ASSOCIATE response failed", "error", err)
		return
	}
	logger.Info("UDP tunnel established", "remote_addr", cfg.RemoteAddr)

	stop := make(chan struct{})
	var stopOnce sync.Once
	stopSession := func() { stopOnce.Do(func() { close(stop) }) }
	defer stopSession()
	go func() {
		_, _ = io.Copy(io.Discard, clientConn)
		stopSession()
	}()
	go func() {
		<-stop
		_ = udpConn.SetReadDeadline(time.Now())
		_ = remoteConn.SetDeadline(time.Now())
	}()

	var clientUDP *net.UDPAddr
	var clientUDPmu sync.Mutex
	responses := make(chan []byte, 128)
	requests := make(chan []byte, udpFrameQueueSize)
	remoteDone := make(chan struct{})
	var uploaded atomic.Uint64
	var downloaded atomic.Uint64
	var dropped atomic.Uint64
	defer func() {
		logger.Info("UDP tunnel closed", "upload_datagrams", uploaded.Load(), "download_datagrams", downloaded.Load(), "dropped_datagrams", dropped.Load(), "duration", time.Since(startedAt))
	}()
	go func() {
		writer := bufio.NewWriterSize(remoteConn, 32*1024)
		for {
			select {
			case packet := <-requests:
				if err := tunnel.WriteQueuedDatagrams(writer, packet, requests); err != nil {
					logger.Debug("send UDP datagram through tunnel failed", "error", err)
					stopSession()
					_ = remoteConn.Close()
					return
				}
			case <-stop:
				return
			}
		}
	}()
	go func() {
		defer close(remoteDone)
		for {
			response, err := tunnel.ReadDatagram(reader)
			if err != nil {
				return
			}
			select {
			case responses <- response:
				downloaded.Add(1)
			case <-stop:
				return
			default:
				dropped.Add(1)
			}
		}
	}()
	go func() {
		for {
			select {
			case response := <-responses:
				clientUDPmu.Lock()
				peer := clientUDP
				clientUDPmu.Unlock()
				if peer != nil {
					_, _ = udpConn.WriteToUDP(response, peer)
				}
			case <-stop:
				return
			}
		}
	}()
	packet := make([]byte, tunnel.MaxDatagramSize+1)
	for {
		_ = udpConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, source, err := udpConn.ReadFromUDP(packet)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-stop:
					return
				case <-remoteDone:
					return
				default:
				}
				continue
			}
			return
		}
		if n > tunnel.MaxDatagramSize {
			dropped.Add(1)
			continue
		}
		clientUDPmu.Lock()
		if clientUDP == nil {
			if request.Address != "" && request.Address != "0.0.0.0" && request.Address != "::" && source.IP.String() != request.Address {
				logger.Warn("drop UDP packet from unexpected client address")
				clientUDPmu.Unlock()
				continue
			}
			clientUDP = source
		}
		if source.String() != clientUDP.String() {
			clientUDPmu.Unlock()
			continue
		}
		clientUDPmu.Unlock()
		destination, payload, err := socks5.ParseUDPDatagram(packet[:n])
		if err != nil {
			logger.Debug("drop malformed SOCKS5 UDP datagram", "error", err)
			continue
		}
		select {
		case requests <- socks5.BuildUDPDatagram(destination, payload):
			uploaded.Add(1)
		case <-stop:
			return
		default:
			dropped.Add(1)
		}
	}
}
