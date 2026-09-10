package adapter

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func waitForSubscribers(t *testing.T, s *urlTestScheduler, key urlTestKey, count int) *urlTestFlight {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		f := s.flights[key]
		ok := f != nil && f.waiters == count
		s.mu.Unlock()
		if ok {
			return f
		}
		runtime.Gosched()
	}
	t.Fatal("subscribers did not reach their barrier")
	return nil
}

func TestURLTestSharedConcurrencyAcrossRequests(t *testing.T) {
	s := newURLTestScheduler(2, 0)
	entered := make(chan struct{}, 10)
	release := make(chan struct{})
	var live, peak atomic.Int32
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = s.do(ctx, urlTestKey{url: fmt.Sprint(i)}, func(ctx context.Context) (uint16, error) {
				n := live.Add(1)
				defer live.Add(-1)
				for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
				}
				entered <- struct{}{}
				select {
				case <-release:
				case <-ctx.Done():
				}
				return 10, nil
			})
		}(i)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("admission stalled")
		}
	}
	if live.Load() != 2 {
		t.Fatalf("active=%d", live.Load())
	}
	close(release)
	wg.Wait()
	if peak.Load() > 2 {
		t.Fatalf("shared peak=%d", peak.Load())
	}
}

func TestURLTestPacingDoesNotAccumulateBurstTokens(t *testing.T) {
	s := newURLTestScheduler(4, time.Second)
	now := time.Unix(100, 0)
	s.now = func() time.Time { return now }
	var waits []time.Duration
	s.wait = func(_ context.Context, d time.Duration) error { waits = append(waits, d); now = now.Add(d); return nil }
	for i := 0; i < 4; i++ {
		if err := s.acquire(context.Background()); err != nil {
			t.Fatal(err)
		}
		<-s.slots
	}
	if len(waits) != 3 {
		t.Fatalf("waits=%v", waits)
	}
	for _, d := range waits {
		if d != time.Second {
			t.Fatalf("spacing=%v", d)
		}
	}
	now = now.Add(time.Hour)
	for i := 0; i < 2; i++ {
		if err := s.acquire(context.Background()); err != nil {
			t.Fatal(err)
		}
		<-s.slots
	}
	if len(waits) != 4 {
		t.Fatalf("idle period accumulated burst allowance: %v", waits)
	}
}

func TestURLTestSharedSubscribersCancelIndependently(t *testing.T) {
	s := newURLTestScheduler(2, 0)
	key := urlTestKey{url: "same", expected: "204"}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), "test-value", "retained"))
	defer cancel()
	entered := make(chan context.Context, 1)
	release := make(chan struct{})
	var calls atomic.Int32
	probe := func(ctx context.Context) (uint16, error) {
		calls.Add(1)
		entered <- ctx
		select {
		case <-release:
			return 42, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { _, err := s.do(ctx, key, probe); first <- err }()
	probeCtx := <-entered
	go func() {
		d, err := s.do(context.Background(), key, probe)
		if d != 42 && err == nil {
			err = fmt.Errorf("delay=%d", d)
		}
		second <- err
	}()
	waitForSubscribers(t, s, key, 2)
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("first=%v", err)
	}
	if probeCtx.Err() != nil {
		t.Fatal("one subscriber cancelled everyone's probe")
	}
	if probeCtx.Value("test-value") != "retained" {
		t.Fatal("dial context values lost")
	}
	close(release)
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("duplicate probes=%d", calls.Load())
	}
}

func TestURLTestCancelledQueuedFlightDoesNotRun(t *testing.T) {
	s := newURLTestScheduler(1, 0)
	// Occupy the resource so the test does not depend on wall-clock sleeps.
	s.slots <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	key := urlTestKey{url: "queued"}
	var calls atomic.Int32
	result := make(chan error, 1)
	go func() {
		_, err := s.do(ctx, key, func(context.Context) (uint16, error) { calls.Add(1); return 1, nil })
		result <- err
	}()
	f := waitForSubscribers(t, s, key, 1)
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	<-f.done
	<-s.slots
	if calls.Load() != 0 {
		t.Fatal("queued probe ran after cancellation")
	}
	if len(s.slots) != 0 {
		t.Fatal("slot leaked")
	}
}

func TestURLTestCancellationWhilePacingReleasesSlot(t *testing.T) {
	s := newURLTestScheduler(1, time.Hour)
	s.lastStart = time.Now()
	waiting := make(chan struct{})
	s.wait = func(ctx context.Context, _ time.Duration) error { close(waiting); <-ctx.Done(); return ctx.Err() }
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- s.acquire(ctx) }()
	<-waiting
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(s.slots) != 0 || len(s.startGate) != 0 {
		t.Fatal("cancelled waiter retained scheduler resources")
	}
}

type failingURLTestAdapter struct {
	C.ProxyAdapter
	started chan struct{}
	wait    bool
}

func (a failingURLTestAdapter) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	if a.started != nil {
		close(a.started)
	}
	if a.wait {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return nil, errors.New("synthetic transport failure")
}

func TestURLTestTransportFailureStillMarksNodeDead(t *testing.T) {
	p := NewProxy(failingURLTestAdapter{})
	_, err := p.urlTest(context.Background(), "http://memory-only.invalid", nil, false)
	if err == nil || p.AliveForTestUrl("another-url") {
		t.Fatal("transport failure did not update health")
	}
}

func TestURLTestUserCancellationPreservesHealthButTimeoutDoesNot(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			started := make(chan struct{})
			p := NewProxy(failingURLTestAdapter{started: started, wait: true})
			ctx, cancel := context.WithCancelCause(context.Background())
			result := make(chan error, 1)
			go func() { _, err := p.urlTest(ctx, "http://memory-only.invalid", nil, false); result <- err }()
			<-started
			cancel(cause)
			if err := <-result; !errors.Is(err, cause) {
				t.Fatal(err)
			}
			wantAlive := errors.Is(cause, context.Canceled)
			if p.AliveForTestUrl("another-url") != wantAlive {
				t.Fatal("incorrect cancellation health policy")
			}
			if wantAlive && len(p.DelayHistory()) != 0 {
				t.Fatal("user cancellation wrote failure history")
			}
		})
	}
}
