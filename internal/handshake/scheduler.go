// Package handshake bounds new TLS connections, independently of business relays.
package handshake

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrFull = errors.New("TLS handshake wait queue full")

type Options struct {
	Rate, Burst, Concurrent, Background, Queue int
	MaxWait                                    time.Duration
}

// Defaults leave room below the standard server's 20/s, burst 40, concurrent 32
// entrance. Other processes / a tighter server policy still require coordination.
func Defaults() Options { return Options{16, 8, 8, 2, 256, 10 * time.Second} }

func (o Options) Validate() error {
	if o.Rate <= 0 || o.Rate > 100000 || o.Burst <= 0 || o.Burst > 1024 || o.Concurrent <= 0 || o.Concurrent > 1024 || o.Background <= 0 || o.Background > o.Concurrent || o.Queue <= 0 || o.Queue > 4096 || o.MaxWait <= 0 || o.MaxWait > time.Minute {
		return errors.New("invalid handshake limits")
	}
	return nil
}

type waiter struct{ background bool }
type Scheduler struct {
	mu                 sync.Mutex
	opts               Options
	changed            chan struct{}
	queue              []*waiter
	tokens             float64
	last               time.Time
	active, background int
	stats              Stats
}
type Stats struct {
	Active, Waiting, BackgroundActive                  int
	Foreground, Background, Queued, Rejected, Canceled uint64
	Wait, MaxWait                                      time.Duration
}

func New(o Options) *Scheduler {
	if o.Validate() != nil {
		panic("invalid handshake limits")
	}
	return &Scheduler{opts: o, changed: make(chan struct{}), tokens: float64(o.Burst), last: time.Now()}
}
func (s *Scheduler) wake() { close(s.changed); s.changed = make(chan struct{}) }
func (s *Scheduler) remove(w *waiter) {
	for i, v := range s.queue {
		if v == w {
			copy(s.queue[i:], s.queue[i+1:])
			s.queue[len(s.queue)-1] = nil
			s.queue = s.queue[:len(s.queue)-1]
			return
		}
	}
}
func (s *Scheduler) head() *waiter {
	for _, w := range s.queue {
		if !w.background {
			return w
		}
	}
	if len(s.queue) > 0 {
		return s.queue[0]
	}
	return nil
}

// Acquire is FIFO within each priority. A foreground waiter overtakes queued
// renewals; at most Background already-running renewals can occupy slots.
// It starts no worker goroutine and is bounded by both caller and local deadline.
func (s *Scheduler) Acquire(ctx context.Context, background bool) (func(), time.Duration, error) {
	if s == nil {
		return func() {}, 0, ctx.Err()
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, s.opts.MaxWait)
	defer cancel()
	s.mu.Lock()
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		return nil, 0, err
	}
	if len(s.queue) >= s.opts.Queue {
		s.stats.Rejected++
		s.mu.Unlock()
		return nil, 0, ErrFull
	}
	w := &waiter{background}
	s.queue = append(s.queue, w)
	s.wake()
	queued := false
	for {
		if err := ctx.Err(); err != nil {
			s.remove(w)
			wait := time.Since(started)
			if !queued {
				s.stats.Queued++
			}
			s.stats.Wait += wait
			s.stats.MaxWait = max(s.stats.MaxWait, wait)
			s.stats.Canceled++
			s.wake()
			s.mu.Unlock()
			return nil, wait, err
		}
		now := time.Now()
		s.tokens = min(float64(s.opts.Burst), s.tokens+now.Sub(s.last).Seconds()*float64(s.opts.Rate))
		s.last = now
		head := s.head() == w
		capacity := s.active < s.opts.Concurrent && (!background || s.background < s.opts.Background)
		if head && capacity && s.tokens >= 1 {
			s.tokens--
			s.remove(w)
			s.active++
			if background {
				s.background++
				s.stats.Background++
			} else {
				s.stats.Foreground++
			}
			wait := time.Duration(0)
			if queued {
				wait = time.Since(started)
				s.stats.Wait += wait
				s.stats.MaxWait = max(s.stats.MaxWait, wait)
			}
			s.wake()
			s.mu.Unlock()
			return sync.OnceFunc(func() {
				s.mu.Lock()
				s.active--
				if background {
					s.background--
				}
				s.wake()
				s.mu.Unlock()
			}), wait, nil
		}
		if !queued {
			queued = true
			s.stats.Queued++
		}
		changed := s.changed
		var timer *time.Timer
		var tick <-chan time.Time
		if head && capacity && s.tokens < 1 {
			timer = time.NewTimer(time.Duration((1-s.tokens)/float64(s.opts.Rate)*float64(time.Second)) + time.Microsecond)
			tick = timer.C
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
		case <-changed:
		case <-tick:
		}
		if timer != nil {
			timer.Stop()
		}
		s.mu.Lock()
	}
}
func (s *Scheduler) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.stats
	v.Active = s.active
	v.BackgroundActive = s.background
	v.Waiting = len(s.queue)
	return v
}

type key struct{}

func WithScheduler(ctx context.Context, s *Scheduler) context.Context {
	return context.WithValue(ctx, key{}, s)
}
func FromContext(ctx context.Context) *Scheduler { s, _ := ctx.Value(key{}).(*Scheduler); return s }
