package operations

import (
	"bufio"
	"context"
	"errors"
	"mygotunnel/internal/datagram"
	"mygotunnel/internal/quicstream"
	"mygotunnel/internal/quicudp"
	"mygotunnel/internal/tunnel"
	"net"
	"time"
)

func probeTCPStreamControl(parent context.Context, addr, sni, pin, token string) (err error) {
	ctx, cancel := context.WithTimeout(parent, quicHealthTimeout)
	defer cancel()
	defer func() {
		if err != nil {
			if ctx.Err() != nil {
				err = ctx.Err()
			} else if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
				var timeout net.Error
				if errors.As(err, &timeout) && timeout.Timeout() {
					err = context.DeadlineExceeded
				}
			}
		}
	}()
	tc, err := quicudp.ClientTLSConfig(addr, sni, pin)
	if err != nil {
		return err
	}
	resources := datagram.NewResources(2, 262144)
	defer resources.Close()
	pool := quicstream.NewPool(addr, tc, resources)
	defer pool.Close()
	c, _, err := pool.Open(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err = c.SetDeadline(deadline); err != nil {
		return err
	}
	if err = tunnel.SendAuth(c, token); err != nil {
		return err
	}
	line, err := tunnel.ReadLine(bufio.NewReader(c))
	if err != nil {
		return err
	}
	if line != "OK" {
		return errors.New("QUIC TCP control rejected")
	}
	return nil
}
