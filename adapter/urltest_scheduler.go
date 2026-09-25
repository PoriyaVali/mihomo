package adapter

import (
	"context"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/utils"
)

// All Proxy.URLTest entry points (API, groups and provider checks) share this
// gate. These are resource/pacing defaults, NOT a measured safe carrier rate.
// No burst tokens accumulate while idle. Normal proxy traffic is unaffected.
// Ten slots (was four, 2026-09-25, owner: "the same ten as sing-box"): a
// dead node holds a slot for its whole budget, so four slots let two or three
// dead nodes stall a sweep. The 250 ms admission spacing is unchanged - it is
// the RATE of new handshakes, and a burst of them is what Hamrah-e Aval
// punishes (measured 2026-09-09: six quick handshakes, then ~1 min of failed
// connects).
var sharedURLTests = newURLTestScheduler(10, 250*time.Millisecond)

type urlTestKey struct {
	proxy         *Proxy
	url, expected string
	unified       bool
}

type urlTestFlight struct {
	done    chan struct{}
	cancel  context.CancelCauseFunc
	waiters int
	delay   uint16
	err     error
}

type urlTestScheduler struct {
	mu        sync.Mutex
	flights   map[urlTestKey]*urlTestFlight
	slots     chan struct{}
	startGate chan struct{}
	lastStart time.Time // Owned by startGate.
	interval  time.Duration
	now       func() time.Time
	wait      func(context.Context, time.Duration) error
}

func newURLTestScheduler(concurrency int, interval time.Duration) *urlTestScheduler {
	return &urlTestScheduler{
		flights:   make(map[urlTestKey]*urlTestFlight),
		slots:     make(chan struct{}, concurrency),
		startGate: make(chan struct{}, 1), interval: interval,
		now: time.Now, wait: waitForURLTest,
	}
}

func (s *urlTestScheduler) run(ctx context.Context, p *Proxy, url string, expected utils.IntRanges[uint16], unified bool) (uint16, error) {
	key := urlTestKey{proxy: p, url: url, expected: expected.String(), unified: unified}
	return s.do(ctx, key, func(probeCtx context.Context) (uint16, error) {
		return p.urlTest(probeCtx, url, expected, unified)
	})
}

// Subscribers have independent deadlines. Only the last subscriber leaving
// cancels shared work; closing a node sheet must not cancel a provider's probe.
func (s *urlTestScheduler) do(ctx context.Context, key urlTestKey, probe func(context.Context) (uint16, error)) (uint16, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	f := s.flights[key]
	if f == nil {
		probeCtx, cancel := context.WithCancelCause(urlTestValues{ctx})
		f = &urlTestFlight{done: make(chan struct{}), cancel: cancel}
		s.flights[key] = f
		go s.execute(probeCtx, key, f, probe)
	}
	f.waiters++
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		s.mu.Lock()
		f.waiters--
		if f.waiters == 0 {
			if s.flights[key] == f {
				delete(s.flights, key)
			}
			f.cancel(ctx.Err())
		}
		s.mu.Unlock()
		return 0, ctx.Err()
	case <-f.done:
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		return f.delay, f.err
	}
}

func (s *urlTestScheduler) execute(ctx context.Context, key urlTestKey, f *urlTestFlight, probe func(context.Context) (uint16, error)) {
	defer func() {
		s.mu.Lock()
		if s.flights[key] == f {
			delete(s.flights, key)
		}
		close(f.done)
		s.mu.Unlock()
		f.cancel(context.Canceled)
	}()
	if f.err = s.acquire(ctx); f.err != nil {
		return
	}
	defer func() { <-s.slots }()
	if f.err = ctx.Err(); f.err != nil {
		return
	}
	// The caller deadlines still cancel via subscriber accounting. This is an
	// additional ceiling for clients that supplied no deadline at all.
	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	f.delay, f.err = probe(probeCtx)
}

// acquire retains a concurrency slot on success, releases it on every failure.
func (s *urlTestScheduler) acquire(ctx context.Context) (err error) {
	if err = ctx.Err(); err != nil {
		return
	}
	select {
	case s.slots <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() {
		if err != nil {
			<-s.slots
		}
	}()
	if err = ctx.Err(); err != nil {
		return
	}
	select {
	case s.startGate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.startGate }()
	if err = ctx.Err(); err != nil {
		return
	}
	if wait := s.lastStart.Add(s.interval).Sub(s.now()); wait > 0 {
		if err = s.wait(ctx, wait); err != nil {
			return
		}
	}
	if err = ctx.Err(); err != nil {
		return
	}
	s.lastStart = s.now()
	return nil
}

func waitForURLTest(ctx context.Context, wait time.Duration) error {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Retain dial-related context values without attaching a shared probe to just
// its first subscriber's cancellation. Compatible with the module's Go 1.20.
type urlTestValues struct{ context.Context }

func (urlTestValues) Deadline() (time.Time, bool) { return time.Time{}, false }
func (urlTestValues) Done() <-chan struct{}       { return nil }
func (urlTestValues) Err() error                  { return nil }
