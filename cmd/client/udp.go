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
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

type udpSourceLookup func(context.Context, string) ([]net.IPAddr, error)

// resolveUDPAssociateSource interprets the UDP ASSOCIATE address as the
// client's expected UDP source. An unspecified address means the client did
// not know its UDP endpoint when it created the association, so use the TCP
// control peer as the fallback. Resolve domains once, before accepting packets.
func resolveUDPAssociateSource(ctx context.Context, source string, peer net.IP, lookup udpSourceLookup) ([]net.IP, byte, error) {
	fallback := func() ([]net.IP, byte, error) {
		if len(peer) == 0 {
			return nil, 0x01, errors.New("SOCKS5 UDP control peer has no IP address")
		}
		return []net.IP{append(net.IP(nil), peer...)}, 0, nil
	}
	if source == "" {
		return fallback()
	}
	if ip := net.ParseIP(source); ip != nil {
		if ip.IsUnspecified() {
			return fallback()
		}
		return []net.IP{ip}, 0, nil
	}
	addresses, err := lookup(ctx, source)
	if err != nil {
		return nil, 0x04, fmt.Errorf("resolve SOCKS5 UDP source: %w", err)
	}
	allowed := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		if len(address.IP) == 0 || address.IP.IsUnspecified() || address.IP.IsMulticast() {
			continue
		}
		duplicate := false
		for _, existing := range allowed {
			if existing.Equal(address.IP) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			allowed = append(allowed, append(net.IP(nil), address.IP...))
		}
	}
	if len(allowed) == 0 {
		return nil, 0x02, errors.New("SOCKS5 UDP source domain resolved to no usable addresses")
	}
	return allowed, 0, nil
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
	allowedSources, rep, err := []net.IP{tcpPeer.IP}, byte(0), error(nil)
	port := request.Port
	if cfg.UDPSourceMode() == "nat" {
		// The declaration can describe the endpoint before NAT. The authenticated
		// TCP peer remains the IP boundary; learn only its mapped UDP port.
		port = 0
	} else {
		resolveCtx, resolveCancel := context.WithTimeout(ctx, socks5Timeout)
		allowedSources, rep, err = resolveUDPAssociateSource(resolveCtx, request.Address, tcpPeer.IP, lookup)
		resolveCancel()
	}
	if err != nil {
		logging.Failure(logger, "udp_source", err)
		_ = socks5.Reply(clientConn, rep)
		return
	}
	filter := newUDPSourceFilter(allowedSources, port)
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
	udpConn, err := listenUDPRelay(bindIP, cfg)
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
		"udp_source_policy", cfg.UDPSourceMode(), "udp_relay_port", bound.Port,
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

	var clientUDP netip.AddrPort
	var clientUDPmu sync.Mutex
	maxBytes, maxAge := cfg.QueueLimits()
	responses := datagram.NewQueue(128, maxBytes, maxAge, nil, resources)
	requests := datagram.NewQueue(udpFrameQueueSize, maxBytes, maxAge, nil, resources)
	tunnelWriter := tunnel.NewDatagramWriter(remoteConn, cfg.WriteTimeout())
	var uploaded atomic.Uint64
	var downloaded atomic.Uint64
	var dropped atomic.Uint64
	var writeErrors atomic.Uint64
	var received, sourceIPDrops, sourcePortDrops, bindingDrops, invalidDrops, oversizedDrops uint64
	var firstDatagramAt time.Time
	readyAt := time.Now()
	defer func() {
		stopSession("udp_session", nil)
		workers.Wait()
		requests.Close()
		responses.Close()
		in, out := requests.Stats(), responses.Stats()
		var firstDuration time.Duration
		if !firstDatagramAt.IsZero() {
			firstDuration = firstDatagramAt.Sub(readyAt)
		}
		logging.LogUDPResult(logger, resources, closeStage, closeErr, tunnelWriter.Stats(), "upload_datagrams", uploaded.Load(), "download_datagrams", downloaded.Load(),
			"received_datagrams", received, "source_ip_drops", sourceIPDrops, "source_port_drops", sourcePortDrops,
			"source_binding_drops", bindingDrops, "invalid_datagrams", invalidDrops, "oversized_datagrams", oversizedDrops,
			"first_datagram_seen", !firstDatagramAt.IsZero(), "first_datagram_duration", firstDuration,
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
				if peer.IsValid() {
					if err := udpConn.SetWriteDeadline(time.Now().Add(maxAge)); err != nil {
						writeErrors.Add(1)
						dropped.Add(1)
						response.Release()
						continue
					}
					if _, err := udpConn.WriteToUDPAddrPort(response.Data, peer); err != nil {
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
		n, source, err := udpConn.ReadFromUDPAddrPort(packet)
		if err != nil {
			stopSession("udp_read", err)
			return
		}
		received++
		if firstDatagramAt.IsZero() {
			firstDatagramAt = time.Now()
		}
		source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
		if n > tunnel.MaxDatagramSize {
			oversizedDrops++
			dropped.Add(1)
			continue
		}
		if reason := filter.rejection(source); reason != "" {
			switch reason {
			case "ip":
				sourceIPDrops++
			case "port":
				sourcePortDrops++
			case "binding":
				bindingDrops++
			}
			dropped.Add(1)
			continue
		}
		if err := socks5.ValidateUDPDatagram(packet[:n]); err != nil {
			invalidDrops++
			dropped.Add(1)
			logger.Debug("drop malformed SOCKS5 UDP datagram", "error", err)
			continue
		}
		clientUDPmu.Lock()
		if !clientUDP.IsValid() {
			clientUDP = source
			filter.bound = source
		}
		clientUDPmu.Unlock()
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
