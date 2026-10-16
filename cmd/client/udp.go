package main

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"mygotunnel/internal/config"
	"mygotunnel/internal/logging"
	"mygotunnel/internal/preconnect"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

func handleUDPAssociate(parent context.Context, clientConn net.Conn, request socks5.Request, cfg *config.ClientConfig, logger *slog.Logger, startedAt time.Time, releaseSetup func(), pool *preconnect.Pool) {
	const udpFrameQueueSize = 256
	tcpPeer, ok := clientConn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		logger.Warn("SOCKS5 UDP control peer is not TCP")
		_ = socks5.Reply(clientConn, 0x01)
		return
	}
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

	socksDuration := time.Since(startedAt)
	ctx, cancel := context.WithTimeout(parent, remoteDialTimeout+tunnel.ControlTimeout)
	session, err := openRemoteUDP(ctx, cfg, pool)
	cancel()
	if err != nil {
		logging.Failure(logger, session.Stage, err)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}
	remoteConn, reader := session.Conn, session.Reader
	defer remoteConn.Close()

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
	if err := remoteConn.SetDeadline(time.Time{}); err != nil {
		logging.Failure(logger, "control", err)
		return
	}
	if err := clientConn.SetDeadline(time.Time{}); err != nil {
		logging.Failure(logger, "socks", err)
		return
	}
	releaseSetup()
	logger.Info("ready", "transport", "udp", "remote_addr", cfg.RemoteAddr,
		"socks_duration", socksDuration, "pool_hit", session.PoolHit,
		"pool_fallback", session.PoolFallback, "pool_acquire_duration", session.PoolAcquireDuration,
		"tcp_duration", session.Dial.TCPDuration, "tls_duration", session.Dial.TLSDuration,
		"control_duration", session.ControlDuration, "setup_duration", time.Since(startedAt))

	stop := make(chan struct{})
	var stopOnce sync.Once
	stopSession := func() {
		stopOnce.Do(func() {
			close(stop)
			_ = udpConn.Close()
			if err := remoteConn.SetDeadline(time.Now()); err != nil {
				_ = remoteConn.Close()
			}
			if err := clientConn.SetReadDeadline(time.Now()); err != nil {
				_ = clientConn.Close()
			}
		})
	}
	var workers sync.WaitGroup

	var clientUDP *net.UDPAddr
	var clientUDPmu sync.Mutex
	responses := make(chan []byte, 128)
	requests := make(chan []byte, udpFrameQueueSize)
	var uploaded atomic.Uint64
	var downloaded atomic.Uint64
	var dropped atomic.Uint64
	var writeErrors atomic.Uint64
	defer func() {
		stopSession()
		workers.Wait()
		logger.Info("closed", "transport", "udp", "upload_datagrams", uploaded.Load(), "download_datagrams", downloaded.Load(), "dropped_datagrams", dropped.Load(), "udp_write_errors", writeErrors.Load(), "duration", time.Since(startedAt))
	}()
	workers.Add(4)
	go func() {
		defer workers.Done()
		_, _ = io.Copy(io.Discard, clientConn)
		stopSession()
	}()
	go func() {
		defer workers.Done()
		writer := bufio.NewWriterSize(remoteConn, 32*1024)
		for {
			select {
			case packet := <-requests:
				if err := tunnel.WriteQueuedDatagrams(writer, packet, requests); err != nil {
					logger.Debug("send UDP datagram through tunnel failed", "error", err)
					stopSession()
					return
				}
			case <-stop:
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		defer stopSession()
		for {
			response, err := tunnel.ReadDatagram(reader)
			if err != nil {
				return
			}
			select {
			case responses <- response:
			case <-stop:
				return
			default:
				dropped.Add(1)
			}
		}
	}()
	go func() {
		defer workers.Done()
		for {
			select {
			case response := <-responses:
				clientUDPmu.Lock()
				peer := clientUDP
				clientUDPmu.Unlock()
				if peer != nil {
					if _, err := udpConn.WriteToUDP(response, peer); err != nil {
						writeErrors.Add(1)
						dropped.Add(1)
					} else {
						downloaded.Add(1)
					}
				}
			case <-stop:
				return
			}
		}
	}()
	packet := make([]byte, tunnel.MaxDatagramSize+1)
	for {
		n, source, err := udpConn.ReadFromUDP(packet)
		if err != nil {
			return
		}
		if n > tunnel.MaxDatagramSize {
			dropped.Add(1)
			continue
		}
		if !source.IP.Equal(tcpPeer.IP) ||
			(request.Port != 0 && source.Port != int(request.Port)) ||
			(request.Address != "" && request.Address != "0.0.0.0" && request.Address != "::" && source.IP.String() != request.Address) {
			dropped.Add(1)
			continue
		}
		if _, _, err := socks5.ParseUDPDatagram(packet[:n]); err != nil {
			dropped.Add(1)
			logger.Debug("drop malformed SOCKS5 UDP datagram", "error", err)
			continue
		}
		clientUDPmu.Lock()
		if clientUDP == nil {
			clientUDP = source
		}
		matchesPeer := source.IP.Equal(clientUDP.IP) && source.Port == clientUDP.Port && source.Zone == clientUDP.Zone
		clientUDPmu.Unlock()
		if !matchesPeer {
			dropped.Add(1)
			continue
		}
		select {
		case requests <- append([]byte(nil), packet[:n]...):
			uploaded.Add(1)
		case <-stop:
			return
		default:
			dropped.Add(1)
		}
	}
}
