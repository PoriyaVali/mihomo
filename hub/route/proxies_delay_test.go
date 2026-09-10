package route

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
)

type delayTestWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (w *delayTestWriter) Header() http.Header    { return w.header }
func (w *delayTestWriter) WriteHeader(status int) { w.status = status }
func (w *delayTestWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.body.Write(b)
}

type delayTestProxy struct {
	C.Proxy
	test func(context.Context, string, utils.IntRanges[uint16]) (uint16, error)
}

func (p delayTestProxy) URLTest(ctx context.Context, url string, expected utils.IntRanges[uint16]) (uint16, error) {
	return p.test(ctx, url, expected)
}

func delayRequest(t *testing.T, ctx context.Context, p C.Proxy) *delayTestWriter {
	t.Helper()
	req, err := http.NewRequest("GET", "http://memory-only.invalid/proxies/node/delay?url=https%3A%2F%2Fmemory-only.invalid%2Fgenerate_204&expected=204&timeout=5000", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(context.WithValue(ctx, CtxKeyProxy, p))
	w := &delayTestWriter{header: make(http.Header)}
	getProxyDelay(w, req)
	return w
}

func TestDelayHandlerEnforcesStatusAndReturnsSafeMessage(t *testing.T) {
	for _, status := range []uint16{204, 302, 403, 500} {
		t.Run(http.StatusText(int(status)), func(t *testing.T) {
			p := delayTestProxy{test: func(ctx context.Context, url string, expected utils.IntRanges[uint16]) (uint16, error) {
				if !expected.Check(204) || expected.Check(403) {
					t.Fatal("expected status not passed to proxy")
				}
				if status == 204 {
					return 12, nil
				}
				return 12, adapter.UnexpectedStatusError{Status: status, Expected: expected}
			}}
			w := delayRequest(t, context.Background(), p)
			var body map[string]any
			if err := json.Unmarshal(w.body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if status == 204 {
				if w.status != 200 || body["delay"] != float64(12) {
					t.Fatalf("status=%d body=%v", w.status, body)
				}
			} else {
				if w.status != 503 || body["message"] == nil || body["delay"] != nil {
					t.Fatalf("status=%d body=%v", w.status, body)
				}
			}
		})
	}
}

func TestDelayHandlerInheritsRequestCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := delayTestProxy{test: func(probeCtx context.Context, _ string, _ utils.IntRanges[uint16]) (uint16, error) {
		if !errors.Is(probeCtx.Err(), context.Canceled) {
			t.Fatal("HTTP cancellation was replaced by a background context")
		}
		return 0, probeCtx.Err()
	}}
	w := delayRequest(t, ctx, p)
	if w.status != 504 {
		t.Fatalf("status=%d", w.status)
	}
}

func TestDelayHandlerDoesNotExposeTransportCredentials(t *testing.T) {
	p := delayTestProxy{test: func(context.Context, string, utils.IntRanges[uint16]) (uint16, error) {
		return 0, errors.New("synthetic socks://user:secret@node.invalid error")
	}}
	w := delayRequest(t, context.Background(), p)
	if w.status != 503 || bytes.Contains(w.body.Bytes(), []byte("secret")) {
		t.Fatalf("unsafe response: %s", w.body.String())
	}
}
