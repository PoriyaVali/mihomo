package http

import (
	"bufio"
	"encoding/base64"
	"net"
	stdhttp "net/http"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/auth"
	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
)

// recordingTunnel answers every forwarded connection with a small HTTP
// response and records the identity the listener attributed it to.
type recordingTunnel struct{ users chan string }

func (t *recordingTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	defer conn.Close()
	t.users <- metadata.InUser
	if _, e := stdhttp.ReadRequest(bufio.NewReader(conn)); e == nil {
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	}
}
func (t *recordingTunnel) HandleUDPPacket(C.UDPPacket, *C.Metadata) {}
func (t *recordingTunnel) NatTable() C.NatTable                     { return nil }

func proxyConn(t *testing.T, tunnel C.Tunnel) (net.Conn, *bufio.Reader) {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = l.Close() })
	store := authStore.NewAuthStore(auth.NewAuthenticator([]auth.AuthUser{{User: "alice", Pass: "secret"}, {User: "bob", Pass: "other"}}))
	go func() {
		c, e := l.Accept()
		if e == nil {
			HandleConn(c, tunnel, store)
		}
	}()
	c, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	return c, bufio.NewReader(c)
}

func proxyRequest(t *testing.T, c net.Conn, r *bufio.Reader, method, target, credential string) *stdhttp.Response {
	t.Helper()
	request := method + " " + target + " HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n"
	if credential != "" {
		request += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(credential)) + "\r\n"
	}
	if _, e := c.Write([]byte(request + "\r\n")); e != nil {
		t.Fatal(e)
	}
	resp, e := stdhttp.ReadResponse(r, &stdhttp.Request{Method: method})
	if e != nil {
		t.Fatal(e)
	}
	if method != stdhttp.MethodConnect {
		_ = resp.Body.Close()
	}
	return resp
}

func TestKeepAliveRequestWithFailedCredentialsIsRejected(t *testing.T) {
	tunnel := &recordingTunnel{users: make(chan string, 4)}
	c, r := proxyConn(t, tunnel)
	if resp := proxyRequest(t, c, r, stdhttp.MethodGet, "http://example.com/", "alice:secret"); resp.StatusCode != stdhttp.StatusOK {
		t.Fatalf("authenticated request: %s", resp.Status)
	}
	if user := <-tunnel.users; user != "alice" {
		t.Fatalf("first request attributed to %q", user)
	}
	// A later request on the same connection names another account with a
	// wrong password. It must neither be served nor carry that identity.
	if resp := proxyRequest(t, c, r, stdhttp.MethodConnect, "example.com:443", "bob:wrong"); resp.StatusCode != stdhttp.StatusForbidden {
		t.Fatalf("failed credentials were served: %s", resp.Status)
	}
	select {
	case user := <-tunnel.users:
		t.Fatalf("rejected request reached the tunnel as %q", user)
	default:
	}
}

func TestKeepAliveRequestWithoutCredentialsKeepsVerifiedUser(t *testing.T) {
	tunnel := &recordingTunnel{users: make(chan string, 4)}
	c, r := proxyConn(t, tunnel)
	if resp := proxyRequest(t, c, r, stdhttp.MethodGet, "http://example.com/", "alice:secret"); resp.StatusCode != stdhttp.StatusOK {
		t.Fatalf("authenticated request: %s", resp.Status)
	}
	<-tunnel.users
	if resp := proxyRequest(t, c, r, stdhttp.MethodConnect, "example.com:443", ""); resp.StatusCode != stdhttp.StatusOK {
		t.Fatalf("follow-up request: %s", resp.Status)
	}
	if user := <-tunnel.users; user != "alice" {
		t.Fatalf("follow-up request attributed to %q, want the verified user", user)
	}
}
