//go:build linux || darwin

package anytls

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

type wrapped struct{ net.Conn }

func (w wrapped) Upstream() any { return w.Conn }

func notSent(t *testing.T, c *net.TCPConn) int {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		v, gerr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT)
	}); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	return v
}

// The session's socket, even under the wrappers dialers put around it, must
// hold no more than notSentLowat bytes unsent.
func TestLimitUnsentReachesTheSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for _, wrap := range []bool{false, true} {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		var conn net.Conn = c
		if wrap {
			conn = wrapped{wrapped{c}}
		}
		limitUnsent(conn)
		if got := notSent(t, c.(*net.TCPConn)); got != notSentLowat {
			t.Fatalf("wrapped=%v: TCP_NOTSENT_LOWAT = %d, want %d", wrap, got, notSentLowat)
		}
		c.Close()
	}
}
