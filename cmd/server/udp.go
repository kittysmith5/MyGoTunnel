package main

import (
	"bufio"
	"context"
	"errors"
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

type udpTargetFailures struct {
	dial, dns, write, read atomic.Uint64
}

func handleUDPTunnel(tunnelConn net.Conn, reader *bufio.Reader, logger *slog.Logger, startedAt time.Time, idleDuration time.Duration, releaseSetup func(), queueConfig config.UDPQueueConfig, limits ...*datagram.Resources) {
	dialer := &net.Dialer{}
	handleUDPTunnelWithDial(tunnelConn, reader, logger, startedAt, idleDuration, releaseSetup, queueConfig, dialer.DialContext, limits...)
}

func handleUDPTunnelWithDial(tunnelConn net.Conn, reader *bufio.Reader, logger *slog.Logger, startedAt time.Time, idleDuration time.Duration, releaseSetup func(), queueConfig config.UDPQueueConfig, dial udpDialFunc, limits ...*datagram.Resources) {
	resources := datagram.SelectResources(limits)
	replyStarted := time.Now()
	if err := tunnel.SendTargetResult(tunnelConn, nil); err != nil {
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
	var closeStage string
	var closeErr error
	stop := func(stage string, cause error) {
		stopOnce.Do(func() {
			closeStage, closeErr = stage, cause
			cancel()
			tunnel.AbortDatagramConn(tunnelConn)
		})
	}
	var workers sync.WaitGroup
	maxBytes, maxAge := queueConfig.QueueLimits()
	requests := datagram.NewQueue(udpFrameQueueSize, maxBytes, maxAge, nil, resources)
	responses := datagram.NewQueue(udpFrameQueueSize, maxBytes, maxAge, nil, resources)
	tunnelWriter := tunnel.NewDatagramWriter(tunnelConn, queueConfig.WriteTimeout())
	// All per-target pending queues share a separate session-wide byte budget.
	pendingBudget := datagram.NewBudget(maxBytes)
	dnsSlots := make(chan struct{}, udpDNSConcurrency)
	targetSlots := make(chan struct{}, udpTargetLimit)
	targets := make(map[string]*udpTarget)
	var downloaded, droppedResponses, uploaded, droppedRequests atomic.Uint64
	var targetFailures udpTargetFailures
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
	sweepTargets := func(now time.Time) {
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
	defer func() {
		stop("udp_session", nil)
		for _, target := range targets {
			retire(target)
		}
		workers.Wait()
		requests.Close()
		responses.Close()
		in, out := requests.Stats(), responses.Stats()
		logging.LogUDPResult(logger, resources, closeStage, closeErr, tunnelWriter.Stats(),
			"target_dial_failures", targetFailures.dial.Load(), "target_dns_failures", targetFailures.dns.Load(),
			"target_write_failures", targetFailures.write.Load(), "target_read_failures", targetFailures.read.Load(),
			"upload_datagrams", uploaded.Load(), "download_datagrams", downloaded.Load(),
			"dropped_requests", droppedRequests.Load(), "dropped_responses", droppedResponses.Load(),
			"queue_full_drops", in.FullDrops+out.FullDrops+targetFull,
			"queue_expired_drops", in.ExpiredDrops+out.ExpiredDrops+targetExpired,
			"queue_resource_drops", in.ResourceDrops+out.ResourceDrops,
			"request_queue_peak_bytes", in.PeakBytes, "response_queue_peak_bytes", out.PeakBytes,
			"target_queue_peak_bytes", targetPeakBytes,
			"expired_targets", expiredTargets, "peak_targets", peakTargets,
			"duration", time.Since(startedAt))
	}()

	workers.Add(2)
	go func() {
		defer workers.Done()
		frames := tunnel.NewDatagramReader(reader, resources)
		for {
			packet, err := frames.ReadPacket()
			if err != nil {
				if errors.Is(err, datagram.ErrResourceLimit) {
					droppedRequests.Add(1)
					continue
				}
				stop("udp_tunnel_read", err)
				return
			}
			if !requests.Push(packet) {
				packet.Release()
				droppedRequests.Add(1)
			}
			if ctx.Err() != nil {
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		writer := bufio.NewWriterSize(tunnelWriter, 32*1024)
		for {
			select {
			case <-responses.Ready():
				if err := tunnel.WriteDatagramQueue(writer, responses); err != nil {
					logger.Debug("write tunneled UDP response failed", "error", err)
					stop("udp_tunnel_write", err)
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
			header, payload, err := socks5.ParseUDPHeader(frame.Data)
			if err != nil {
				frame.Release()
				droppedRequests.Add(1)
				logger.Debug("drop invalid tunneled UDP packet", "error", err)
				continue
			}
			// A lookup-only []byte-to-string conversion does not allocate. Copy the
			// header key and format the dial address only when creating a target.
			key := frame.Data[3:header.Size]
			// Pending target queues own the parsed payload slice and retain its
			// original age; target workers need no second header parse/allocation.
			frame.Data = payload
			target := targets[string(key)]
			if target != nil && target.failed.Load() {
				retire(target)
				delete(targets, string(key))
				target = nil
			}
			if target == nil {
				// Failed targets can release their socket between periodic sweeps.
				// Reclaim their map entries before rejecting an unrelated target;
				// targetSlots still bounds workers whose I/O has not stopped yet.
				if len(targets) >= udpTargetLimit {
					sweepTargets(time.Now())
				}
				if len(targets) >= udpTargetLimit {
					frame.Release()
					droppedRequests.Add(1)
					continue
				}
				// Retired workers still count until all of their I/O has stopped.
				select {
				case targetSlots <- struct{}{}:
				default:
					frame.Release()
					droppedRequests.Add(1)
					continue
				}
				if !resources.AcquireSocket() {
					<-targetSlots
					frame.Release()
					droppedRequests.Add(1)
					continue
				}
				targetCtx, targetCancel := context.WithCancel(ctx)
				destination := socks5.UDPDatagram{Host: header.Host(), Port: header.Port}
				address := net.JoinHostPort(destination.Host, strconv.Itoa(int(destination.Port)))
				target = &udpTarget{
					destination: destination, cancel: targetCancel,
					pending: datagram.NewQueue(udpTargetQueueSize, min(udpTargetQueueBytes, maxBytes), maxAge, pendingBudget, resources),
				}
				if !target.pending.Push(frame) {
					frame.Release()
					retire(target)
					<-targetSlots
					resources.ReleaseSocket()
					droppedRequests.Add(1)
					continue
				}
				target.lastActivity.Store(time.Now().UnixNano())
				targets[string(key)] = target
				peakTargets = max(peakTargets, len(targets))
				workers.Add(1)
				go func(targetCtx context.Context, target *udpTarget, address string) {
					defer workers.Done()
					defer func() { <-targetSlots; resources.ReleaseSocket() }()
					runUDPTarget(targetCtx, target, address, dial, dnsSlots, responses, &uploaded, &downloaded, &droppedResponses, logger, &targetFailures)
				}(targetCtx, target, address)
				continue
			}
			if !target.pending.Push(frame) {
				frame.Release()
				droppedRequests.Add(1)
			}
		case now := <-ticker.C:
			sweepTargets(now)
		}
	}
}

// A bounded worker owns each target's dial and writes. Slow DNS or socket writes
// never run in the association dispatcher. Numeric targets bypass DNS slots.
func runUDPTarget(ctx context.Context, target *udpTarget, address string, dial udpDialFunc, dnsSlots chan struct{}, responses *datagram.Queue, uploaded, downloaded, dropped *atomic.Uint64, logger *slog.Logger, failures *udpTargetFailures) {
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
		if ctx.Err() == nil {
			failures.dial.Add(1)
			var dns *net.DNSError
			if errors.As(err, &dns) {
				failures.dns.Add(1)
			}
		}
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
		readUDPResponses(target, responses, ctx.Done(), downloaded, dropped, logger, failures)
	}()
	defer func() { target.cancel(); _ = conn.Close(); <-readerDone }()
	for ctx.Err() == nil {
		packet, ok := target.pending.Pop(ctx)
		if !ok {
			return
		}
		if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			if ctx.Err() == nil {
				failures.write.Add(1)
			}
			packet.Release()
			return
		}
		_, err := conn.Write(packet.Data)
		packet.Release()
		if err != nil {
			if ctx.Err() == nil {
				failures.write.Add(1)
			}
			logger.Debug("write target UDP failed", "error", err)
			return
		}
		target.lastActivity.Store(time.Now().UnixNano())
		uploaded.Add(1)
	}
}

func readUDPResponses(target *udpTarget, responses *datagram.Queue, done <-chan struct{}, downloaded, dropped *atomic.Uint64, logger *slog.Logger, failures ...*udpTargetFailures) {
	defer func() {
		target.failed.Store(true)
		_ = target.conn.Close()
	}()
	header := socks5.BuildUDPDatagram(target.destination, nil)
	// Leave one extra byte to detect oversized/truncated payloads, including
	// their SOCKS header. Build the invariant header only once per target.
	resources := responses.Resources()
	scratch, err := resources.Borrow(tunnel.MaxDatagramSize + 1)
	if err != nil {
		dropped.Add(1)
		logger.Debug("UDP response buffer limit", "error", err)
		return
	}
	defer scratch.Release()
	buffer := scratch.Data
	copy(buffer, header)
	for {
		n, err := target.conn.Read(buffer[len(header):])
		if err != nil {
			select {
			case <-done:
			default:
				if len(failures) > 0 && !errors.Is(err, net.ErrClosed) {
					failures[0].read.Add(1)
				}
			}
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
