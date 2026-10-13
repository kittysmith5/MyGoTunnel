// Package admission bounds setup and accepted connections independently.
package admission

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Permit supports temporarily releasing setup capacity while an authenticated
// connection waits in the idle pool, then reacquiring before target dial.
type Permit struct {
	mu    sync.Mutex
	slots chan struct{}
	held  bool
}

func (p *Permit) Release() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.held {
		<-p.slots
		p.held = false
	}
}

func (p *Permit) TryAcquire() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.held {
		return true
	}
	select {
	case p.slots <- struct{}{}:
		p.held = true
		return true
	default:
		return false
	}
}

// Serve retains the simple handler API. An optional total limit includes active
// relays; zero means no total limit. Handlers own and must close their connection.
func Serve(listener net.Listener, maxSetup int, handler func(net.Conn, func()), onOverload func(), maxConnections ...int) error {
	total := 0
	if len(maxConnections) > 0 {
		total = maxConnections[0]
	}
	return ServeWithPermit(listener, maxSetup, total, func(c net.Conn, p *Permit) { handler(c, p.Release) }, onOverload)
}

func ServeWithPermit(listener net.Listener, maxSetup, maxConnections int, handler func(net.Conn, *Permit), onOverload func()) error {
	if maxSetup <= 0 {
		return fmt.Errorf("max-setup must be positive")
	}
	if maxConnections < 0 {
		return fmt.Errorf("max-connections must not be negative")
	}
	slots := make(chan struct{}, maxSetup)
	var connections chan struct{}
	if maxConnections > 0 {
		connections = make(chan struct{}, maxConnections)
	}
	reject := func(c net.Conn) {
		_ = c.Close()
		if onOverload != nil {
			onOverload()
		}
	}
	var delay time.Duration
	for {
		c, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var temporary net.Error
			if errors.As(err, &temporary) && temporary.Temporary() {
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else {
					delay *= 2
				}
				if delay > time.Second {
					delay = time.Second
				}
				time.Sleep(delay)
				continue
			}
			return fmt.Errorf("accept connection: %w", err)
		}
		delay = 0
		if connections != nil {
			select {
			case connections <- struct{}{}:
			default:
				reject(c)
				continue
			}
		}
		select {
		case slots <- struct{}{}:
			permit := &Permit{slots: slots, held: true}
			go func() {
				if connections != nil {
					defer func() { <-connections }()
				}
				defer permit.Release()
				handler(c, permit)
			}()
		default:
			if connections != nil {
				<-connections
			}
			reject(c)
		}
	}
}
