package main

import (
	"bufio"
	"context"
	"log/slog"
	"mygotunnel/internal/logging"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	udpTargetLimit       = 256
	udpTargetIdleTimeout = 2 * time.Minute
	udpTargetSweepPeriod = 15 * time.Second
	udpFrameQueueSize    = 256
)

type udpTarget struct {
	conn         net.Conn
	destination  socks5.UDPDatagram
	lastActivity atomic.Int64
	failed       atomic.Bool
}

func handleUDPTunnel(tunnelConn net.Conn, reader *bufio.Reader, logger *slog.Logger, startedAt time.Time, idleDuration time.Duration, releaseSetup func()) {
	replyStarted := time.Now()
	if err := tunnel.SendOK(tunnelConn); err != nil {
		logger.Warn("send UDP response failed", "error", err)
		return
	}
	if err := tunnelConn.SetDeadline(time.Time{}); err != nil {
		logging.Failure(logger, "control", err)
		return
	}
	releaseSetup()
	logger.Info("ready", "transport", "udp", "setup_duration", time.Since(startedAt)-idleDuration, "reply_duration", time.Since(replyStarted))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			close(done)
			cancel()
			if err := tunnelConn.SetDeadline(time.Now()); err != nil {
				_ = tunnelConn.Close()
			}
		})
	}
	var workers sync.WaitGroup
	requests := make(chan []byte, udpFrameQueueSize)
	responses := make(chan []byte, udpFrameQueueSize)
	targets := make(map[string]*udpTarget)
	var downloaded atomic.Uint64
	var droppedResponses atomic.Uint64
	var uploaded uint64
	var expiredTargets uint64
	peakTargets := 0
	defer func() {
		stop()
		for _, target := range targets {
			_ = target.conn.Close()
		}
		workers.Wait()
		logger.Info("closed", "transport", "udp",
			"upload_datagrams", uploaded,
			"download_datagrams", downloaded.Load(),
			"dropped_responses", droppedResponses.Load(),
			"expired_targets", expiredTargets,
			"peak_targets", peakTargets,
			"duration", time.Since(startedAt),
		)
	}()

	workers.Add(2)
	go func() {
		defer workers.Done()
		for {
			packet, err := tunnel.ReadDatagram(reader)
			if err != nil {
				stop()
				return
			}
			select {
			case requests <- packet:
			case <-done:
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		writer := bufio.NewWriterSize(tunnelConn, 32*1024)
		for {
			select {
			case packet := <-responses:
				if err := tunnel.WriteQueuedDatagrams(writer, packet, responses); err != nil {
					logger.Debug("write tunneled UDP response failed", "error", err)
					stop()
					_ = tunnelConn.Close()
					return
				}
			case <-done:
				return
			}
		}
	}()
	ticker := time.NewTicker(udpTargetSweepPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case frame := <-requests:
			destination, payload, err := socks5.ParseUDPDatagram(frame)
			if err != nil {
				logger.Debug("drop invalid tunneled UDP packet", "error", err)
				continue
			}
			address := net.JoinHostPort(destination.Host, strconv.Itoa(int(destination.Port)))
			target := targets[address]
			if target != nil && target.failed.Load() {
				_ = target.conn.Close()
				delete(targets, address)
				target = nil
			}
			if target == nil {
				if len(targets) >= udpTargetLimit {
					logger.Debug("UDP session destination limit reached")
					continue
				}
				dialer := &net.Dialer{Timeout: 5 * time.Second}
				conn, err := dialer.DialContext(ctx, "udp", address)
				if err != nil {
					logger.Debug("UDP target dial failed", "error", err)
					continue
				}
				target = &udpTarget{conn: conn, destination: destination}
				target.lastActivity.Store(time.Now().UnixNano())
				targets[address] = target
				if len(targets) > peakTargets {
					peakTargets = len(targets)
				}
				workers.Add(1)
				go func(target *udpTarget) {
					defer workers.Done()
					readUDPResponses(target, responses, done, &downloaded, &droppedResponses, logger)
				}(target)
			}
			if err := target.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				_ = target.conn.Close()
				delete(targets, address)
				continue
			}
			if _, err := target.conn.Write(payload); err != nil {
				logger.Debug("write target UDP failed", "error", err)
				_ = target.conn.Close()
				delete(targets, address)
				continue
			}
			target.lastActivity.Store(time.Now().UnixNano())
			uploaded++
		case now := <-ticker.C:
			for address, target := range targets {
				last := time.Unix(0, target.lastActivity.Load())
				if now.Sub(last) >= udpTargetIdleTimeout {
					_ = target.conn.Close()
					delete(targets, address)
					expiredTargets++
				}
			}
		}
	}
}

func readUDPResponses(target *udpTarget, responses chan<- []byte, done <-chan struct{}, downloaded, dropped *atomic.Uint64, logger *slog.Logger) {
	defer func() {
		target.failed.Store(true)
		_ = target.conn.Close()
	}()
	buffer := make([]byte, tunnel.MaxDatagramSize)
	for {
		n, err := target.conn.Read(buffer)
		if err != nil {
			target.failed.Store(true)
			logger.Debug("read target UDP failed", "error", err)
			return
		}
		target.lastActivity.Store(time.Now().UnixNano())
		packet := socks5.BuildUDPDatagram(target.destination, buffer[:n])
		if len(packet) > tunnel.MaxDatagramSize {
			dropped.Add(1)
			continue
		}
		select {
		case responses <- packet:
			downloaded.Add(1)
		case <-done:
			return
		default:
			dropped.Add(1)
			logger.Debug("drop UDP response because tunnel queue is full")
		}
	}
}
