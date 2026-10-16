package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mygotunnel/internal/config"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/logging"
	"mygotunnel/internal/preconnect"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type udpSourceLookup func(context.Context, string) ([]net.IPAddr, error)

// A source domain is a declaration of the UDP sender, not a destination to
// resolve for every packet. Authorize it once, then keep the TCP peer IP rule.
func validateUDPAssociateSource(ctx context.Context, source string, peer net.IP, lookup udpSourceLookup) (byte, error) {
	if source == "" {
		return 0, nil
	}
	if ip := net.ParseIP(source); ip != nil {
		if ip.IsUnspecified() || ip.Equal(peer) {
			return 0, nil
		}
		return 0x02, errors.New("SOCKS5 UDP source does not match TCP peer")
	}
	addresses, err := lookup(ctx, source)
	if err != nil {
		return 0x04, fmt.Errorf("resolve SOCKS5 UDP source: %w", err)
	}
	for _, address := range addresses {
		if address.IP.Equal(peer) {
			return 0, nil
		}
	}
	return 0x02, errors.New("SOCKS5 UDP source domain does not include TCP peer")
}

func handleUDPAssociate(parent context.Context, clientConn net.Conn, request socks5.Request, cfg *config.ClientConfig, logger *slog.Logger, startedAt time.Time, releaseSetup func(), pool *preconnect.Pool, limits ...*datagram.Resources) {
	handleUDPAssociateWithResolver(parent, clientConn, request, cfg, logger, startedAt, releaseSetup, pool, net.DefaultResolver.LookupIPAddr, limits...)
}

func handleUDPAssociateWithResolver(parent context.Context, clientConn net.Conn, request socks5.Request, cfg *config.ClientConfig, logger *slog.Logger, startedAt time.Time, releaseSetup func(), pool *preconnect.Pool, lookup udpSourceLookup, limits ...*datagram.Resources) {
	const udpFrameQueueSize = 256
	resources := datagram.SelectResources(limits)
	tcpPeer, ok := clientConn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		logger.Warn("SOCKS5 UDP control peer is not TCP")
		_ = socks5.Reply(clientConn, 0x01)
		return
	}
	ctx, cancel := context.WithTimeout(parent, remoteSetupTimeout)
	defer cancel()
	resolveCtx, resolveCancel := context.WithTimeout(ctx, socks5Timeout)
	rep, err := validateUDPAssociateSource(resolveCtx, request.Address, tcpPeer.IP, lookup)
	resolveCancel()
	if err != nil {
		logging.Failure(logger, "udp_source", err)
		_ = socks5.Reply(clientConn, rep)
		return
	}
	if !resources.AcquireSocket() {
		logging.Failure(logger, "udp_bind", datagram.ErrResourceLimit)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}
	defer resources.ReleaseSocket()
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
	scratch, err := resources.Borrow(tunnel.MaxDatagramSize + 1)
	if err != nil {
		logging.Failure(logger, "udp_bind", err)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}
	defer scratch.Release()

	socksDuration := time.Since(startedAt)
	session, err := openRemoteUDP(ctx, cfg, pool)
	cancel()
	if err != nil {
		logging.Failure(logger, session.Stage, err)
		_ = socks5.Reply(clientConn, socks5.ReplyCode(err))
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
		"pool_ack_duration", session.AckDuration,
		"tcp_duration", session.Dial.TCPDuration, "tls_duration", session.Dial.TLSDuration,
		"control_duration", session.ControlDuration, "setup_duration", time.Since(startedAt))

	stop := make(chan struct{})
	var stopOnce sync.Once
	var closeStage string
	var closeErr error
	stopSession := func(stage string, cause error) {
		stopOnce.Do(func() {
			closeStage, closeErr = stage, cause
			close(stop)
			_ = udpConn.Close()
			tunnel.AbortDatagramConn(remoteConn)
			if err := clientConn.SetReadDeadline(time.Now()); err != nil {
				_ = clientConn.Close()
			}
		})
	}
	var workers sync.WaitGroup

	var clientUDP *net.UDPAddr
	var clientUDPmu sync.Mutex
	maxBytes, maxAge := cfg.QueueLimits()
	responses := datagram.NewQueue(128, maxBytes, maxAge, nil, resources)
	requests := datagram.NewQueue(udpFrameQueueSize, maxBytes, maxAge, nil, resources)
	tunnelWriter := tunnel.NewDatagramWriter(remoteConn, cfg.WriteTimeout())
	var uploaded atomic.Uint64
	var downloaded atomic.Uint64
	var dropped atomic.Uint64
	var writeErrors atomic.Uint64
	defer func() {
		stopSession("udp_session", nil)
		workers.Wait()
		requests.Close()
		responses.Close()
		in, out := requests.Stats(), responses.Stats()
		logging.LogUDPResult(logger, resources, closeStage, closeErr, tunnelWriter.Stats(), "upload_datagrams", uploaded.Load(), "download_datagrams", downloaded.Load(),
			"dropped_datagrams", dropped.Load()+in.ExpiredDrops+out.ExpiredDrops,
			"queue_full_drops", in.FullDrops+out.FullDrops, "queue_expired_drops", in.ExpiredDrops+out.ExpiredDrops,
			"queue_resource_drops", in.ResourceDrops+out.ResourceDrops,
			"request_queue_peak_bytes", in.PeakBytes, "response_queue_peak_bytes", out.PeakBytes,
			"udp_write_errors", writeErrors.Load(), "duration", time.Since(startedAt))
	}()
	workers.Add(4)
	go func() {
		defer workers.Done()
		_, err := io.Copy(io.Discard, clientConn)
		stopSession("udp_control", err)
	}()
	go func() {
		defer workers.Done()
		writer := bufio.NewWriterSize(tunnelWriter, 32*1024)
		for {
			select {
			case <-requests.Ready():
				if err := tunnel.WriteDatagramQueue(writer, requests); err != nil {
					logger.Debug("send UDP datagram through tunnel failed", "error", err)
					stopSession("udp_tunnel_write", err)
					return
				}
			case <-stop:
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		frames := tunnel.NewDatagramReader(reader, resources)
		for {
			response, err := frames.ReadPacket()
			if err != nil {
				if errors.Is(err, datagram.ErrResourceLimit) {
					dropped.Add(1)
					continue
				}
				stopSession("udp_tunnel_read", err)
				return
			}
			select {
			case <-stop:
				response.Release()
				return
			default:
			}
			if !responses.Push(response) {
				response.Release()
				dropped.Add(1)
			}
		}
	}()
	go func() {
		defer workers.Done()
		for {
			select {
			case <-responses.Ready():
				response, ok := responses.TryPop()
				if !ok {
					continue
				}
				clientUDPmu.Lock()
				peer := clientUDP
				clientUDPmu.Unlock()
				if peer != nil {
					if err := udpConn.SetWriteDeadline(time.Now().Add(maxAge)); err != nil {
						writeErrors.Add(1)
						dropped.Add(1)
						response.Release()
						continue
					}
					if _, err := udpConn.WriteToUDP(response.Data, peer); err != nil {
						writeErrors.Add(1)
						dropped.Add(1)
					} else {
						downloaded.Add(1)
					}
				}
				response.Release()
			case <-stop:
				return
			}
		}
	}()
	packet := scratch.Data
	for {
		n, source, err := udpConn.ReadFromUDP(packet)
		if err != nil {
			stopSession("udp_read", err)
			return
		}
		if n > tunnel.MaxDatagramSize {
			dropped.Add(1)
			continue
		}
		if !source.IP.Equal(tcpPeer.IP) ||
			(request.Port != 0 && source.Port != int(request.Port)) {
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
		case <-stop:
			return
		default:
		}
		if requests.PushCopy(packet[:n]) {
			uploaded.Add(1)
		} else {
			dropped.Add(1)
		}
	}
}
