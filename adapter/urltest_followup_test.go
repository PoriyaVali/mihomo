// Codex review 2026-09-10. Memory-only tests of actual dm5 code.
// Desired contracts: these were RED against dm5 before the follow-up fix.
package adapter_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

func TestDM5UnexpectedStatusDoesNotPoisonOtherURL(t *testing.T) {
	old := adapter.UnifiedDelay.Load()
	adapter.UnifiedDelay.Store(false)
	defer adapter.UnifiedDelay.Store(old)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	_ = server.SetDeadline(deadline)
	serverResult := make(chan error, 1)
	go func() {
		defer server.Close()
		req, err := http.ReadRequest(bufio.NewReader(server))
		if err != nil {
			serverResult <- err
			return
		}
		if req.Method != "HEAD" {
			serverResult <- fmt.Errorf("unexpected method %s", req.Method)
			return
		}
		time.Sleep(10 * time.Millisecond)
		_, err = io.WriteString(server, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		serverResult <- err
	}()
	p := adapter.NewProxy(contractAdapter{conn: contractConn{raw: client}})
	const checked = "http://memory-only.invalid/generate_204"
	const unrelated = "https://another-unmeasured.invalid/health"
	before := p.AliveForTestUrl(unrelated)
	expected, err := utils.NewUnsignedRanges[uint16]("204")
	if err != nil {
		t.Fatal(err)
	}
	delay, err := p.URLTest(ctx, checked, expected)
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatal(serverErr)
	}
	var mismatch adapter.UnexpectedStatusError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected typed mismatch, got %v", err)
	}
	if p.AliveForTestUrl(checked) {
		t.Fatal("checked URL must fail its expected status")
	}
	after := p.AliveForTestUrl(unrelated)
	t.Logf("HTTP 403; typed error=%v; delay=%d; unrelated URL alive: %v -> %v; global history=%v", err, delay, before, after, p.DelayHistory())
	if after != before {
		t.Fatal("HTTP mismatch poisoned an unrelated, untested URL through global alive")
	}
}

type cancelledProbeAdapter struct {
	C.ProxyAdapter
	name    string
	started *atomic.Int32
}

func (a cancelledProbeAdapter) Name() string { return a.name }
func (a cancelledProbeAdapter) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	a.started.Add(1)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("test expected cancellation before any dial")
}

func TestDM5AlreadyCancelledGroupDoesNotProbeOrChangeHealth(t *testing.T) {
	var started atomic.Int32
	const members = 100
	proxies := make([]C.Proxy, 0, members)
	for i := 0; i < members; i++ {
		proxies = append(proxies, adapter.NewProxy(cancelledProbeAdapter{
			name: fmt.Sprintf("node-%d", i), started: &started,
		}))
	}
	hc := provider.NewHealthCheck(proxies, "", 0, 0, true, nil)
	pd, err := provider.NewCompatibleProvider("cancel-review-provider", proxies, hc)
	if err != nil {
		t.Fatal(err)
	}
	gb := outboundgroup.NewGroupBase(outboundgroup.GroupBaseOption{
		Name: "cancel-review-group", Type: C.URLTest, Providers: []P.ProxyProvider{pd},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // No wall-clock race: cancellation precedes the whole group call.
	_, _ = gb.URLTest(ctx, "http://memory-only.invalid/generate_204", nil)
	changed := 0
	for _, p := range proxies {
		if len(p.DelayHistory()) != 0 {
			changed++
		}
	}
	t.Logf("already cancelled: DialContext entered %d/%d; histories changed %d", started.Load(), members, changed)
	if started.Load() != 0 || changed != 0 {
		t.Fatal("already-cancelled group admitted probes and changed untested node health")
	}
}
