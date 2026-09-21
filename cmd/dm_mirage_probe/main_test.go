package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestDirectTLSNeverAttestsProxyEvidence(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		status, size         int
		insecure, diagnostic bool
	}{
		{"complete", 200, 32768, true, true},
		{"error_page", 403, 32768, true, false},
		{"short_body", 200, 8192, true, false},
		{"untrusted_certificate", 200, 32768, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", fmt.Sprint(tc.size))
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, strings.Repeat("a", tc.size))
			}))
			defer srv.Close()
			host, portString, _ := net.SplitHostPort(srv.Listener.Addr().String())
			port, _ := strconv.Atoi(portString)
			out := run(request{ProtocolVersion: 1, Host: host, Port: port, ServerName: "yahoo.com",
				Offset: 5, Records: 2, PayloadBytes: 32768, TimeoutMs: 3000, InsecureSkipVerify: tc.insecure})
			if out.DiagnosticSucceeded != tc.diagnostic {
				t.Fatalf("unexpected diagnostic: %+v", out)
			}
			if out.OK || out.Authenticated || out.VerifiedHTTPSPayload || out.OutboundRevision != "" || !out.Closed {
				t.Fatalf("fabricated evidence or unclosed transport: %+v", out)
			}
			if out.EvidenceKind != "direct-tls-diagnostic" {
				t.Fatal(out.EvidenceKind)
			}
		})
	}
}

func TestRejectsUnboundedInputsBeforeDial(t *testing.T) {
	base := request{ProtocolVersion: 1, Host: "127.0.0.1", Port: 1, Offset: 5, Records: 2}
	for _, mutate := range []func(*request){
		func(r *request) { r.PayloadBytes = 1 << 30 },
		func(r *request) { r.TimeoutMs = 15001 },
		func(r *request) { r.Records = 1 },
		func(r *request) { r.Offset = -1 },
		func(r *request) { r.Path = "/\r\nInjected: true" },
	} {
		req := base
		mutate(&req)
		out := run(req)
		if out.Reason != "invalid_budget_or_shape" && out.Reason != "invalid_http_target" {
			t.Fatalf("input reached dial: %+v", out)
		}
	}
}
