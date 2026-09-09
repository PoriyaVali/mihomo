// A group-wide URL test must not open every member's connection at once.
//
// It used to. Every proxy in the group started its handshake in the same
// instant, so a seventeen-node group made seventeen simultaneous outbound
// connections - and this call is reachable from the Clash API, from a failed
// dial, and from opening the node list in the UI.
//
// Measured on Hamrah-e Aval on 2026-09-09: six fragmented handshakes in quick
// succession were followed by plain TCP connect() failing eight times in a row
// for close to a minute, with an untouched handshake succeeding immediately
// before and after. Against a censor that behaves that way, an unbounded sweep
// can turn one unreachable node into an outage for the whole device.
//
// These tests use an in-memory adapter and open no sockets.
package outboundgroup

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

// countingAdapter records how many URLTests are in flight at the same moment.
type countingAdapter struct {
	C.ProxyAdapter
	name    string
	live    *atomic.Int32
	peak    *atomic.Int32
	started *atomic.Int32
	hold    time.Duration
}

func (a countingAdapter) Name() string { return a.name }

func (a countingAdapter) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	a.started.Add(1)
	now := a.live.Add(1)
	defer a.live.Add(-1)
	for {
		peak := a.peak.Load()
		if now <= peak || a.peak.CompareAndSwap(peak, now) {
			break
		}
	}
	select {
	case <-time.After(a.hold):
	case <-ctx.Done():
	}
	// Failing the dial is enough: URLTest returns the error and the group
	// records nothing, which is all these tests need.
	return nil, context.DeadlineExceeded
}

func newGroup(t *testing.T, members int, live, peak, started *atomic.Int32, hold time.Duration) *GroupBase {
	t.Helper()
	proxies := make([]C.Proxy, 0, members)
	for i := 0; i < members; i++ {
		proxies = append(proxies, adapter.NewProxy(countingAdapter{
			name: string(rune('a'+i)) + "-node", live: live, peak: peak,
			started: started, hold: hold,
		}))
	}
	// A group reads its members through a provider, so build the same
	// compatible provider the config parser uses. Interval 0 and an empty URL
	// keep the health check from starting any traffic of its own, which would
	// otherwise be counted here.
	hc := provider.NewHealthCheck(proxies, "", 0, 0, true, nil)
	pd, err := provider.NewCompatibleProvider("test-provider", proxies, hc)
	if err != nil {
		t.Fatal(err)
	}
	return NewGroupBase(GroupBaseOption{
		Name:      "test-group",
		Type:      C.URLTest,
		Providers: []P.ProxyProvider{pd},
	})
}

func TestURLTestBoundsConcurrency(t *testing.T) {
	var live, peak, started atomic.Int32
	// Comfortably more members than the limit, so an unbounded implementation
	// cannot pass by accident.
	const members = maxConcurrentURLTests * 3
	gb := newGroup(t, members, &live, &peak, &started, 40*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = gb.URLTest(ctx, "http://memory-only.invalid/generate_204", utils.IntRanges[uint16](nil))

	if got := peak.Load(); got > maxConcurrentURLTests {
		t.Fatalf("%d tests ran at once, limit is %d", got, maxConcurrentURLTests)
	}
	if got := started.Load(); got != members {
		t.Fatalf("every member should still be tested: %d of %d", got, members)
	}
}

// A cancelled caller must stop the queue, not let it drain. Starting the
// remaining handshakes adds attempts nobody is waiting for, which is the
// traffic the bound exists to avoid.
func TestURLTestStopsWhenTheCallerGivesUp(t *testing.T) {
	var live, peak, started atomic.Int32
	const members = maxConcurrentURLTests * 4
	gb := newGroup(t, members, &live, &peak, &started, 200*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = gb.URLTest(ctx, "http://memory-only.invalid/generate_204", utils.IntRanges[uint16](nil))
	}()
	// Long enough for the first batch to be in flight, short enough that the
	// rest are still queued.
	time.Sleep(60 * time.Millisecond)
	cancel()
	wg.Wait()

	if got := started.Load(); got >= members {
		t.Fatalf("cancellation should have left some queued: %d of %d started", got, members)
	}
}
