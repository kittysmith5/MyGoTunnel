package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"sync"
	"time"

	"mygotunnel/internal/config"
	"mygotunnel/internal/quiccfg"
	"mygotunnel/internal/relay"
	"mygotunnel/internal/socks5"
	"mygotunnel/internal/tunnel"

	"github.com/quic-go/quic-go"
)

const nextProto = "mygotunnel-quic"

type quicClient struct {
	remoteAddr string
	tlsConfig  *tls.Config
	quicConfig *quic.Config

	mu   sync.Mutex
	conn *quic.Conn
}

func newQUICClient(remoteAddr string, quicConfig *quic.Config) *quicClient {
	quicConfig = quicConfig.Clone()
	quicConfig.TokenStore = quic.NewLRUTokenStore(4, 4)

	return &quicClient{
		remoteAddr: remoteAddr,
		tlsConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{nextProto},
			ServerName:         remoteServerName(remoteAddr),
		},
		quicConfig: quicConfig,
	}
}

func remoteServerName(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return ""
	}
	return host
}

func (c *quicClient) connect(ctx context.Context) error {
	_, err := c.getConn(ctx)
	return err
}

func (c *quicClient) openStream(ctx context.Context) (*quic.Stream, error) {
	stream, err := c.openStreamWithCachedConn(ctx)
	if err == nil {
		return stream, nil
	}

	if !shouldReconnectQUIC(err) {
		return nil, err
	}

	c.closeCachedConn()
	return c.openStreamWithCachedConn(ctx)
}

func shouldReconnectQUIC(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var streamLimitErr *quic.StreamLimitReachedError
	if errors.As(err, &streamLimitErr) {
		return false
	}

	return true
}

func (c *quicClient) openStreamWithCachedConn(ctx context.Context) (*quic.Stream, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}

	return conn.OpenStreamSync(ctx)
}

func (c *quicClient) getConn(ctx context.Context) (*quic.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		select {
		case <-c.conn.Context().Done():
			c.conn = nil
		default:
			return c.conn, nil
		}
	}

	conn, err := quic.DialAddr(ctx, c.remoteAddr, c.tlsConfig, c.quicConfig)
	if err != nil {
		return nil, err
	}

	c.conn = conn
	return conn, nil
}

func (c *quicClient) closeCachedConn() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return
	}

	_ = c.conn.CloseWithError(0, "")
	c.conn = nil
}

func main() {
	configPath := flag.String("config", "configs/client.json", "config file path")
	flag.Parse()

	cfg, err := config.LoadClientConfig(*configPath)
	if err != nil {
		fmt.Println("[client] load config error:", err)
		return
	}

	ln, err := net.Listen("tcp", cfg.LocalAddr)
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	fmt.Println("[client] SOCKS5 listening on", cfg.LocalAddr)
	fmt.Println("[client] remote QUIC node:", cfg.RemoteAddr)

	remote := newQUICClient(cfg.RemoteAddr, quiccfg.Build(cfg.QUICConfig))
	go warmQUICConnection(remote, cfg.OpenStreamTimeoutSeconds)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("[client] accept error:", err)
			continue
		}

		go handleClient(conn, cfg, remote)
	}
}

func handleClient(clientConn net.Conn, cfg *config.ClientConfig, remote *quicClient) {
	defer clientConn.Close()
	tuneTCP(clientConn)

	clientAddr := clientConn.RemoteAddr().String()
	fmt.Println("[client] connected:", clientAddr)

	_ = clientConn.SetReadDeadline(time.Now().Add(time.Duration(cfg.SocksHandshakeTimeoutSeconds) * time.Second))
	if err := socks5.Handshake(clientConn); err != nil {
		fmt.Println("[client] socks5 handshake error:", err)
		return
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(time.Duration(cfg.SocksRequestTimeoutSeconds) * time.Second))
	targetAddr, err := socks5.ReadRequest(clientConn)
	if err != nil {
		fmt.Println("[client] socks5 request error:", err)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}
	_ = clientConn.SetReadDeadline(time.Time{})

	fmt.Println("[client] target:", targetAddr)

	streamTimeout := time.Duration(cfg.OpenStreamTimeoutSeconds) * time.Second
	streamCtx, cancelStream := context.WithTimeout(context.Background(), streamTimeout)
	stream, err := remote.openStream(streamCtx)
	cancelStream()
	if err != nil {
		fmt.Println("[client] open QUIC stream error:", err)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}
	defer stream.Close()

	_ = stream.SetDeadline(time.Now().Add(streamTimeout))
	remoteReader := bufio.NewReader(stream)

	if err := tunnel.SendAuth(stream, cfg.AuthToken); err != nil {
		fmt.Println("[client] send auth error:", err)
		return
	}

	authResp, err := tunnel.ReadLine(remoteReader)
	if err != nil {
		fmt.Println("[client] read auth response error:", err)
		return
	}

	if authResp != "OK" {
		fmt.Println("[client] auth failed:", authResp)
		return
	}

	if err := tunnel.SendConnect(stream, targetAddr); err != nil {
		fmt.Println("[client] send connect error:", err)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}

	resp, err := tunnel.ReadLine(remoteReader)
	if err != nil {
		fmt.Println("[client] read remote response error:", err)
		_ = socks5.Reply(clientConn, 0x01)
		return
	}

	if resp != "OK" {
		fmt.Println("[client] remote connect failed:", resp)
		_ = socks5.Reply(clientConn, 0x05)
		return
	}

	if err := socks5.Reply(clientConn, 0x00); err != nil {
		fmt.Println("[client] socks5 reply error:", err)
		return
	}

	_ = stream.SetDeadline(time.Time{})
	relay.CopyBidirectional(clientConn, clientConn, stream, remoteReader)

	fmt.Println("[client] closed:", clientAddr)
}

func warmQUICConnection(remote *quicClient, timeoutSeconds int) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	if err := remote.connect(ctx); err != nil {
		fmt.Println("[client] warm QUIC connect error:", err)
	}
}

func tuneTCP(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}
}
