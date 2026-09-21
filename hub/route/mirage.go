package route

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/mirage"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/tls"
)

const mirageEvidenceKind = "authenticated-core-outbound-v1"
const miragePayloadHost = "speed.cloudflare.com"
const miragePayloadURL = "https://speed.cloudflare.com/__down?bytes=32768"

var mirageShapes = []mirage.Shape{{5, 2, false}, {1, 2, false}, {2, 2, false}, {5, 3, false}, {5, 2, true}, {5, 3, true}}

type mirageRequest struct {
	ProtocolVersion  int    `json:"protocolVersion"`
	ID               string `json:"id"`
	OutboundRevision string `json:"outboundRevision"`
	mirage.Shape
}

type mirageJob struct {
	id     string
	cancel context.CancelFunc
	done   chan struct{}
}

var mirageJobs struct {
	sync.Mutex
	active    *mirageJob
	lastID    string
	notBefore time.Time
}

func selectedMirageOutbound() (*outbound.AnyTLS, string) {
	proxy := tunnel.Proxies()["PROXY"]
	metadata := &C.Metadata{NetWork: C.TCP, Host: miragePayloadHost, DstPort: 443}
	for depth := 0; proxy != nil && depth < 16; depth++ {
		if node := outbound.MirageAnyTLS(proxy.Adapter()); node != nil {
			return node, node.MirageRevision()
		}
		// Load-balancing cannot promise the same concrete node on the next dial.
		switch proxy.Adapter().(type) {
		case *outboundgroup.Selector, *outboundgroup.URLTest, *outboundgroup.Fallback:
			proxy = proxy.Unwrap(metadata, false)
		default:
			return nil, ""
		}
	}
	return nil, ""
}

func mirageRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			host, _, err := net.SplitHostPort(req.RemoteAddr)
			if err != nil || !net.ParseIP(host).IsLoopback() || req.Header.Get("Origin") != "" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, req)
		})
	})
	r.Get("/capabilities", func(w http.ResponseWriter, r *http.Request) {
		_, revision := selectedMirageOutbound()
		shapes := []mirage.Shape{}
		if revision != "" {
			shapes = mirageShapes
		}
		render.JSON(w, r, render.M{"protocolVersion": 2, "version": "mihomo-mirage-probe-v1/" + C.Version,
			"evidenceKind": mirageEvidenceKind, "outboundRevision": revision, "shapes": shapes})
	})
	r.Post("/probe", runMirageProbe)
	r.Post("/cancel", cancelMirageProbe)
	return r
}

func readMirageRequest(r *http.Request) (mirageRequest, bool) {
	var req mirageRequest
	err := json.NewDecoder(io.LimitReader(r.Body, 2048)).Decode(&req)
	return req, err == nil && req.ProtocolVersion == 2 && len(req.ID) >= 8 && len(req.ID) <= 96
}

func mirageFailure(reason string) render.M {
	return render.M{"protocolVersion": 2, "ok": false, "closed": true, "reason": reason}
}

func runMirageProbe(w http.ResponseWriter, r *http.Request) {
	req, valid := readMirageRequest(r)
	if !valid || !req.Shape.Valid() {
		render.JSON(w, r, mirageFailure("invalid_request"))
		return
	}
	node, revision := selectedMirageOutbound()
	if revision == "" || revision != req.OutboundRevision {
		render.JSON(w, r, mirageFailure("scope_changed"))
		return
	}
	mirageJobs.Lock()
	if mirageJobs.active != nil || time.Now().Before(mirageJobs.notBefore) {
		mirageJobs.Unlock()
		render.JSON(w, r, mirageFailure("busy_or_cooldown"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	job := &mirageJob{id: req.ID, cancel: cancel, done: make(chan struct{})}
	mirageJobs.active = job
	mirageJobs.Unlock()
	// execute returns only AFTER all transport and cloned-client defers finish.
	result := executeMirageProbe(ctx, node, req.Shape, revision)
	cancel()
	mirageJobs.Lock()
	mirageJobs.active = nil
	mirageJobs.lastID = req.ID
	mirageJobs.notBefore = time.Now().Add(90 * time.Second)
	close(job.done)
	mirageJobs.Unlock()
	render.JSON(w, r, result)
}

func cancelMirageProbe(w http.ResponseWriter, r *http.Request) {
	req, valid := readMirageRequest(r)
	if !valid {
		render.JSON(w, r, render.M{"closed": false})
		return
	}
	mirageJobs.Lock()
	job := mirageJobs.active
	last := mirageJobs.lastID
	mirageJobs.Unlock()
	if job == nil {
		render.JSON(w, r, render.M{"closed": last == req.ID})
		return
	}
	if job.id != req.ID {
		render.JSON(w, r, render.M{"closed": false})
		return
	}
	job.cancel()
	select {
	case <-job.done:
		render.JSON(w, r, render.M{"closed": true})
	case <-time.After(4 * time.Second):
		render.JSON(w, r, render.M{"closed": false})
	}
}

func executeMirageProbe(parent context.Context, node *outbound.AnyTLS, shape mirage.Shape, revision string) render.M {
	clone, err := node.CloneForMirage()
	if err != nil {
		return mirageFailure("unsupported_outbound")
	}
	defer clone.Close()
	ctx, trace := mirage.WithProbe(parent, shape)
	defer trace.Close()
	innerTLS, err := ca.GetTLSConfig(ca.Option{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}})
	if err != nil {
		return mirageFailure("https_config")
	}
	transport := &http.Transport{DisableKeepAlives: true, DisableCompression: true, TLSClientConfig: innerTLS,
		MaxResponseHeaderBytes: 16384,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return clone.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: miragePayloadHost, DstPort: 443})
		},
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, miragePayloadURL, nil)
	if err != nil {
		return mirageFailure("https_request")
	}
	started := time.Now()
	// RoundTrip does not follow redirects. The inner HTTPS peer is always verified.
	response, err := transport.RoundTrip(request)
	if err != nil {
		return mirageFailure("authenticated_https_failed")
	}
	defer response.Body.Close()
	connectMs := (time.Since(started) + time.Millisecond - 1) / time.Millisecond
	if response.StatusCode != 200 {
		return mirageFailure("https_status")
	}
	transferStart := time.Now()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 32769))
	transferMs := (time.Since(transferStart) + time.Millisecond - 1) / time.Millisecond
	if err != nil || len(payload) != 32768 {
		return mirageFailure("https_payload")
	}
	applied, ok := trace.Applied()
	if !ok {
		return mirageFailure("applied_shape_unconfirmed")
	}
	after, afterRevision := selectedMirageOutbound()
	if after != node || afterRevision != revision || parent.Err() != nil {
		return mirageFailure("scope_changed")
	}
	return render.M{"protocolVersion": 2, "evidenceKind": mirageEvidenceKind, "outboundRevision": revision,
		"ok": true, "closed": true, "offset": applied.Offset, "records": applied.Records, "coalesce": applied.Coalesce,
		"authenticated": true, "verifiedHttpsPayload": true, "freshConnection": true, "receivedBytes": len(payload),
		"connectMs": connectMs, "transferMs": transferMs}
}
