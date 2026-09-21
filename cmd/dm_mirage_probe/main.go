// Direct TLS diagnostic ONLY. Not an authenticated proxy/core probe.
// This command is intentionally not packaged or called by Android automatic mode.
// JSON stdin/stdout; sockets close before ANY reply is serialized.
package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/mirage"
)

type request struct {
	ProtocolVersion int    `json:"protocolVersion"`
	Host            string `json:"host"`
	Port            int    `json:"port"`
	ServerName      string `json:"serverName"`
	Offset          int    `json:"offset"`
	Records         int    `json:"records"`
	Coalesce        bool   `json:"coalesce"`
	PayloadBytes    int    `json:"payloadBytes"`
	TimeoutMs       int    `json:"timeoutMs"`
	Path            string `json:"path"`
	// Diagnostic opt-in only; NEVER implies authenticated proxy/HTTPS evidence.
	InsecureSkipVerify bool `json:"insecureSkipVerify"`
}

type response struct {
	OK                   bool   `json:"ok"`
	Closed               bool   `json:"closed"`
	ProtocolVersion      int    `json:"protocolVersion"`
	Version              string `json:"version"`
	EvidenceKind         string `json:"evidenceKind"`
	OutboundRevision     string `json:"outboundRevision"`
	Reason               string `json:"reason"`
	DiagnosticSucceeded  bool   `json:"diagnosticSucceeded"`
	Offset               int    `json:"offset"`
	Records              int    `json:"records"`
	Coalesce             bool   `json:"coalesce"`
	Authenticated        bool   `json:"authenticated"`
	VerifiedHTTPSPayload bool   `json:"verifiedHttpsPayload"`
	FreshConnection      bool   `json:"freshConnection"`
	ReceivedBytes        int    `json:"receivedBytes"`
	ConnectMs            int64  `json:"connectMs"`
	TransferMs           int64  `json:"transferMs"`
	PayloadSHA256        string `json:"payloadSha256,omitempty"`
}

func refused(reason string) response {
	return response{Closed: true, ProtocolVersion: 1,
		Version: "dm-mirage-diagnostic/2", EvidenceKind: "direct-tls-diagnostic", Reason: reason}
}

func main() {
	var req request
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 16384)).Decode(&req); err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(refused("bad_request"))
		return
	}
	// run returns only after its defers close all transports, including failures.
	_ = json.NewEncoder(os.Stdout).Encode(run(req))
}

func run(req request) response {
	if req.ProtocolVersion != 1 {
		return refused("protocol_version")
	}
	if req.Host == "" || req.Port < 1 || req.Port > 65535 {
		return refused("missing_target")
	}
	if req.PayloadBytes == 0 {
		req.PayloadBytes = 32768
	}
	if req.TimeoutMs == 0 {
		req.TimeoutMs = 15000
	}
	if req.PayloadBytes < 1 || req.PayloadBytes > 65536 || req.TimeoutMs < 1 || req.TimeoutMs > 15000 ||
		req.Offset < 1 || req.Offset > 1024 || req.Records < 2 || req.Records > 8 {
		return refused("invalid_budget_or_shape")
	}
	if req.ServerName == "" {
		req.ServerName = req.Host
	}
	if req.Path == "" {
		req.Path = "/"
	}
	if !strings.HasPrefix(req.Path, "/") || strings.ContainsAny(req.Path+req.ServerName, "\r\n") {
		return refused("invalid_http_target")
	}
	httpReq, err := http.NewRequest(http.MethodGet,
		"https://"+net.JoinHostPort(req.ServerName, fmt.Sprint(req.Port))+req.Path, nil)
	if err != nil {
		return refused("invalid_http_target")
	}
	httpReq.Close = true

	start := time.Now()
	deadline := start.Add(time.Duration(req.TimeoutMs) * time.Millisecond)
	raw, err := net.DialTimeout("tcp", net.JoinHostPort(req.Host, fmt.Sprint(req.Port)), time.Until(deadline))
	if err != nil {
		return refused("dial:" + err.Error())
	}
	defer raw.Close()
	_ = raw.SetDeadline(deadline)
	wrapped := mirage.NewConnWithOptions(raw, req.Offset, req.Records, req.Coalesce)
	conn := tls.Client(wrapped, &tls.Config{
		ServerName: req.ServerName, InsecureSkipVerify: req.InsecureSkipVerify, MinVersion: tls.VersionTLS12,
	})
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		return refused("handshake:" + err.Error())
	}
	off, rec, coal, applied := wrapped.AppliedShape()
	if !applied {
		return refused("applied_shape_false")
	}
	out := refused("diagnostic_only_not_proxy_evidence")
	out.Offset, out.Records, out.Coalesce = off, rec, coal
	out.FreshConnection = true
	out.ConnectMs = time.Since(start).Milliseconds() // Includes TLS, not just TCP.
	transferStart := time.Now()
	if err := httpReq.Write(conn); err != nil {
		return refused("http_write:" + err.Error())
	}
	// Bound even hostile headers/chunk framing; never count them as payload.
	reader := bufio.NewReader(io.LimitReader(conn, int64(req.PayloadBytes)+65536))
	res, err := http.ReadResponse(reader, httpReq)
	if err != nil {
		return refused("http_response:" + err.Error())
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return refused("http_status")
	}
	payload := make([]byte, req.PayloadBytes)
	n, err := io.ReadFull(res.Body, payload)
	out.ReceivedBytes = n
	out.TransferMs = time.Since(transferStart).Milliseconds()
	if err != nil {
		out.Reason = "incomplete_payload"
		return out
	}
	sum := sha256.Sum256(payload)
	out.PayloadSHA256 = hex.EncodeToString(sum[:])
	out.DiagnosticSucceeded = true
	// OK/authenticated/verifiedHttpsPayload deliberately remain false. No AnyTLS,
	// REALITY, proxy credentials, selected-core fingerprint or HTTPS origin proof.
	// Never echo a caller-supplied outboundRevision as though it were attested.
	return out
}
