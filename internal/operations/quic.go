package operations

import (
	"bufio"
	"context"
	"errors"
	"net"
	"time"

	"mygotunnel/internal/datagram"
	"mygotunnel/internal/quicudp"
	"mygotunnel/internal/tunnel"
)

const quicHealthTimeout = 3 * time.Second

// probeQUICControl verifies certificate trust, AUTH and UDP setup without
// enabling or sending business datagrams. Its private, small resource budget
// does not consume the service's shared forwarding budget.
func probeQUICControl(parent context.Context, addr, sni, pin, token string) (err error) {
	ctx, cancel := context.WithTimeout(parent, quicHealthTimeout)
	defer cancel()
	defer func() {
		if err != nil {
			if ctx.Err() != nil {
				err = ctx.Err()
			} else if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
				// A socket deadline can fire just before the context timer runs.
				var timeout net.Error
				if errors.As(err, &timeout) && timeout.Timeout() {
					err = context.DeadlineExceeded
				}
			}
		}
	}()
	tlsConfig, err := quicudp.ClientTLSConfig(addr, sni, pin)
	if err != nil {
		return err
	}
	resources := datagram.NewResources(1, 256<<10)
	defer resources.Close()
	conn, err := quicudp.Dial(ctx, addr, tlsConfig, resources, datagram.DefaultMaxAge)
	if err != nil {
		return err
	}
	defer conn.Close()
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(closed)
		_ = conn.Close()
	})
	defer func() {
		if stop() {
			close(closed)
		}
		<-closed
	}()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	if err := tunnel.SendUDPSetup(conn, token); err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	for range 2 {
		line, err := tunnel.ReadLine(reader)
		if err != nil {
			return err
		}
		if line != "OK" {
			return errors.New("QUIC control rejected")
		}
	}
	if reader.Buffered() != 0 {
		return errors.New("unexpected QUIC control data")
	}
	return nil
}

func localListenerAddress(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}
	if host == "" {
		host = "127.0.0.1"
	} else if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		if ip.To4() == nil {
			host = "::1"
		} else {
			host = "127.0.0.1"
		}
	}
	return net.JoinHostPort(host, port), nil
}
