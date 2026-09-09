// URLTest must tell the caller when the status was not the one asked for.
//
// Written by Codex as a handoff fixture and kept here as a regression test,
// because the defect it catches is invisible from the outside: URLTest
// computed `satisfied`, recorded it against the per-URL state, and then
// returned nil error with a positive delay anyway. An endpoint answering 403
// or 500 was reported to the caller as a healthy proxy.
//
// That matters beyond tidiness. Any measurement built on this call - including
// the node sweeps used to decide which TLS shape survives a carrier - counted
// those as successes. The criterion has to be right before the numbers mean
// anything.
//
// The last case is the one to be careful with: a caller that asks for nothing
// still accepts anything, so this cannot break existing unconditional health
// checks.
package adapter_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
)

type contractConn struct {
	C.Conn
	raw net.Conn
}

func (c contractConn) Read(b []byte) (int, error)         { return c.raw.Read(b) }
func (c contractConn) Write(b []byte) (int, error)        { return c.raw.Write(b) }
func (c contractConn) Close() error                       { return c.raw.Close() }
func (c contractConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c contractConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c contractConn) SetDeadline(v time.Time) error      { return c.raw.SetDeadline(v) }
func (c contractConn) SetReadDeadline(v time.Time) error  { return c.raw.SetReadDeadline(v) }
func (c contractConn) SetWriteDeadline(v time.Time) error { return c.raw.SetWriteDeadline(v) }

type contractAdapter struct {
	C.ProxyAdapter
	conn C.Conn
}

func (f contractAdapter) Name() string { return "memory-only-contract-test" }
func (f contractAdapter) DialContext(context.Context, *C.Metadata) (C.Conn, error) {
	return f.conn, nil
}

func TestURLTestEnforcesExplicitExpectedStatus(t *testing.T) {
	old := adapter.UnifiedDelay.Load()
	adapter.UnifiedDelay.Store(false)
	defer adapter.UnifiedDelay.Store(old)
	for _, tc := range []struct {
		name     string
		status   int
		expected string
		wantErr  bool
	}{
		{"204_matches", 204, "204", false},
		{"redirect_is_not_204", 302, "204", true},
		{"403_is_not_204", 403, "204", true},
		{"500_is_not_204", 500, "204", true},
		{"unspecified_preserves_old_accept_any", 403, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// An in-memory pipe, not a socket or real server.
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			server.SetDeadline(deadline)
			serverResult := make(chan error, 1)
			go func() {
				defer server.Close()
				req, err := http.ReadRequest(bufio.NewReader(server))
				if err != nil {
					serverResult <- err
					return
				}
				if req.Method != "HEAD" {
					serverResult <- fmt.Errorf("unexpected method: %s", req.Method)
					return
				}
				// Avoid conflating this test with the legacy zero-ms sentinel.
				time.Sleep(10 * time.Millisecond)
				_, err = io.WriteString(server, fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", tc.status, http.StatusText(tc.status)))
				serverResult <- err
			}()
			proxy := adapter.NewProxy(contractAdapter{conn: contractConn{raw: client}})
			expected, err := utils.NewUnsignedRanges[uint16](tc.expected)
			if err != nil {
				t.Fatal(err)
			}
			delay, err := proxy.URLTest(ctx, "http://memory-only.invalid/generate_204", expected)
			if serverErr := <-serverResult; serverErr != nil {
				t.Fatal(serverErr)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("HTTP %d expected=%q: error=%v delay=%d; wantErr=%v", tc.status, tc.expected, err, delay, tc.wantErr)
			}
		})
	}
}
