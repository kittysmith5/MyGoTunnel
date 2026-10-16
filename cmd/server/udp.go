package main

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/logging"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
)

const (
	udpTargetLimit       = 256
	udpTargetIdleTimeout = 2 * time.Minute
	udpTargetSweepPeriod = 15 * time.Second
	udpFrameQueueSize    = 256
	udpTargetQueueSize   = 32
	udpTargetQueueBytes  = 64 * 1024
	udpDNSConcurrency    = 16
)

type udpTarget struct {
	conn         net.Conn // set by the target worker before starting its response reader
	destination  socks5.UDPDatagram
	pending      *datagram.Queue
	cancel       context.CancelFunc
	lastActivity atomic.Int64
	failed       atomic.Bool
}

type udpDialFunc func(context.Context, string, string) (net.Conn, error)

func handleUDPTunnel(tunnelConn net.Conn, reader *bufio.Reader, logger *slog.Logger, startedAt time.Time, idleDuration time.Duration, releaseSetup func(), queueConfig config.UDPQueueConfig) {
	dialer := &net.Dialer{}
	handleUDPTunnelWithDial(tunnelConn, reader, logger, startedAt, idleDuration, releaseSetup, queueConfig, dialer.DialContext)
}

func handleUDPTunnelWithDial(tunnelConn net.Conn, reader *bufio.Reader, logger *slog.Logger, startedAt time.Time, idleDuration time.Duration, releaseSetup func(), queueConfig config.UDPQueueConfig, dial udpDialFunc) {
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
	done := ctx.Done()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel()
			if err := tunnelConn.SetDeadline(time.Now()); err != nil {
				_ = tunnelConn.Close()
			}
		})
	}
	var workers sync.WaitGroup
	maxBytes, maxAge := queueConfig.QueueLimits()
	requests := datagram.NewQueue(udpFrameQueueSize, maxBytes, maxAge, nil)
	responses := datagram.NewQueue(udpFrameQueueSize, maxBytes, maxAge, nil)
	// All per-target pending queues share a separate session-wide byte budget.
	pendingBudget := datagram.NewBudget(maxBytes)
	dnsSlots := make(chan struct{}, udpDNSConcurrency)
	targetSlots := make(chan struct{}, udpTargetLimit)
	targets := make(map[string]*udpTarget)
	var downloaded, droppedResponses, uploaded, droppedRequests atomic.Uint64
	var targetFull, targetExpired, targetPeakBytes uint64
	var expiredTargets uint64
	peakTargets := 0
	retire := func(target *udpTarget) {
		target.cancel()
		target.pending.Close()
		stats := target.pending.Stats()
		targetFull += stats.FullDrops
		targetExpired += stats.ExpiredDrops
		targetPeakBytes = max(targetPeakBytes, uint64(stats.PeakBytes))
	}
	defer func() {
		stop()
		for _, target := range targets {
			retire(target)
		}
		workers.Wait()
		requests.Close()
		responses.Close()
		in, out := requests.Stats(), responses.Stats()
		logger.Info("closed", "transport", "udp",
			"upload_datagrams", uploaded.Load(), "download_datagrams", downloaded.Load(),
			"dropped_requests", droppedRequests.Load(), "dropped_responses", droppedResponses.Load(),
			"queue_full_drops", in.FullDrops+out.FullDrops+targetFull,
			"queue_expired_drops", in.ExpiredDrops+out.ExpiredDrops+targetExpired,
			"request_queue_peak_bytes", in.PeakBytes, "response_queue_peak_bytes", out.PeakBytes,
			"target_queue_peak_bytes", targetPeakBytes,
			"expired_targets", expiredTargets, "peak_targets", peakTargets,
			"duration", time.Since(startedAt))
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
			if !requests.Push(datagram.Packet{Data: packet}) {
				droppedRequests.Add(1)
			}
			if ctx.Err() != nil {
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		writer := bufio.NewWriterSize(tunnelConn, 32*1024)
		for {
			select {
			case <-responses.Ready():
				if err := tunnel.WriteDatagramQueue(writer, responses); err != nil {
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
		case <-requests.Ready():
			frame, ok := requests.TryPop()
			if !ok {
				continue
			}
			destination, payload, err := socks5.ParseUDPDatagram(frame.Data)
			if err != nil {
				droppedRequests.Add(1)
				logger.Debug("drop invalid tunneled UDP packet", "error", err)
				continue
			}
			address := net.JoinHostPort(destination.Host, strconv.Itoa(int(destination.Port)))
			// Pending target queues own the parsed payload slice and retain its
			// original age; target workers need no second header parse/allocation.
			frame.Data = payload
			target := targets[address]
			if target != nil && target.failed.Load() {
				retire(target)
				delete(targets, address)
				target = nil
			}
			if target == nil {
				if len(targets) >= udpTargetLimit {
					droppedRequests.Add(1)
					continue
				}
				// Retired workers still count until all of their I/O has stopped.
				select {
				case targetSlots <- struct{}{}:
				default:
					droppedRequests.Add(1)
					continue
				}
				targetCtx, targetCancel := context.WithCancel(ctx)
				target = &udpTarget{
					destination: destination, cancel: targetCancel,
					pending: datagram.NewQueue(udpTargetQueueSize, min(udpTargetQueueBytes, maxBytes), maxAge, pendingBudget),
				}
				if !target.pending.Push(frame) {
					retire(target)
					<-targetSlots
					droppedRequests.Add(1)
					continue
				}
				target.lastActivity.Store(time.Now().UnixNano())
				targets[address] = target
				peakTargets = max(peakTargets, len(targets))
				workers.Add(1)
				go func(targetCtx context.Context, target *udpTarget, address string) {
					defer workers.Done()
					defer func() { <-targetSlots }()
					runUDPTarget(targetCtx, target, address, dial, dnsSlots, responses, &uploaded, &downloaded, &droppedResponses, logger)
				}(targetCtx, target, address)
				continue
			}
			if !target.pending.Push(frame) {
				droppedRequests.Add(1)
			}
		case now := <-ticker.C:
			for address, target := range targets {
				last := time.Unix(0, target.lastActivity.Load())
				idleExpired := now.Sub(last) >= udpTargetIdleTimeout
				if target.failed.Load() || idleExpired {
					retire(target)
					delete(targets, address)
					if idleExpired {
						expiredTargets++
					}
				}
			}
		}
	}
}

// A bounded worker owns each target's dial and writes. Slow DNS or socket writes
// never run in the association dispatcher. Numeric targets bypass DNS slots.
func runUDPTarget(ctx context.Context, target *udpTarget, address string, dial udpDialFunc, dnsSlots chan struct{}, responses *datagram.Queue, uploaded, downloaded, dropped *atomic.Uint64, logger *slog.Logger) {
	defer func() {
		target.failed.Store(true)
		target.cancel()
		target.pending.Close()
	}()
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	var conn net.Conn
	var err error
	if net.ParseIP(target.destination.Host) == nil {
		select {
		case dnsSlots <- struct{}{}:
			conn, err = dial(dialCtx, "udp", address)
			<-dnsSlots
		case <-dialCtx.Done():
			err = dialCtx.Err()
		}
	} else {
		conn, err = dial(dialCtx, "udp", address)
	}
	cancel()
	if err != nil {
		logger.Debug("UDP target dial failed", "error", err)
		return
	}
	target.conn = conn
	defer conn.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		defer target.cancel()
		readUDPResponses(target, responses, ctx.Done(), downloaded, dropped, logger)
	}()
	defer func() { target.cancel(); _ = conn.Close(); <-readerDone }()
	for ctx.Err() == nil {
		packet, ok := target.pending.Pop(ctx)
		if !ok {
			return
		}
		if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return
		}
		if _, err := conn.Write(packet.Data); err != nil {
			logger.Debug("write target UDP failed", "error", err)
			return
		}
		target.lastActivity.Store(time.Now().UnixNano())
		uploaded.Add(1)
	}
}

func readUDPResponses(target *udpTarget, responses *datagram.Queue, done <-chan struct{}, downloaded, dropped *atomic.Uint64, logger *slog.Logger) {
	defer func() {
		target.failed.Store(true)
		_ = target.conn.Close()
	}()
	header := socks5.BuildUDPDatagram(target.destination, nil)
	// Leave one extra byte to detect oversized/truncated payloads, including
	// their SOCKS header. Build the invariant header only once per target.
	buffer := make([]byte, tunnel.MaxDatagramSize+1)
	copy(buffer, header)
	for {
		n, err := target.conn.Read(buffer[len(header):])
		if err != nil {
			target.failed.Store(true)
			logger.Debug("read target UDP failed", "error", err)
			return
		}
		target.lastActivity.Store(time.Now().UnixNano())
		packet := buffer[:len(header)+n]
		if len(packet) > tunnel.MaxDatagramSize {
			dropped.Add(1)
			continue
		}
		select {
		case <-done:
			return
		default:
		}
		if responses.PushCopy(packet) {
			downloaded.Add(1)
		} else {
			dropped.Add(1)
		}
	}
}
