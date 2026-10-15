package session

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/anytls/util"
)

// slowDial is a server that takes delay to complete each handshake.
func slowDial(t *testing.T, delay time.Duration) (util.DialOutFunc, *atomic.Int32) {
	var dials atomic.Int32
	return func(ctx context.Context) (net.Conn, error) {
		dials.Add(1)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		c, s := net.Pipe()
		t.Cleanup(func() { c.Close(); s.Close() })
		go io.Copy(io.Discard, s)
		return c, nil
	}, &dials
}

func idleCount(c *Client) int {
	c.idleSessionLock.Lock()
	defer c.idleSessionLock.Unlock()
	return c.idleSession.Len()
}

// 🔴 A handshake that outlasts the request that started it must not be thrown
// away. mihomo allows a proxy dial five seconds, TLS included; where a
// handshake takes longer, every request began one, each was cut off, and no
// session was ever made. The handshake now finishes and waits in the pool for
// the next request.
func TestSlowHandshakeServesTheNextRequest(t *testing.T) {
	dial, dials := slowDial(t, 300*time.Millisecond)
	c := NewClient(context.Background(), dial, defaultPadding(), "", 0, 0, 0, false)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, err := c.CreateStream(ctx)
	cancel()
	if err == nil {
		t.Fatal("a request whose deadline passed during the handshake got a stream")
	}
	deadline := time.Now().Add(3 * time.Second)
	for idleCount(c) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the finished handshake never reached the pool")
		}
		time.Sleep(10 * time.Millisecond)
	}

	start := time.Now()
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	st, err := c.CreateStream(ctx2)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if took := time.Since(start); took > 150*time.Millisecond {
		t.Fatalf("the next request waited %v, for a handshake of its own", took)
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("dialled %d times, want the one handshake reused", n)
	}
}

// Without reuse there is no pool: a handshake finished too late is closed.
func TestSlowHandshakeWithoutReuseIsClosed(t *testing.T) {
	dial, _ := slowDial(t, 200*time.Millisecond)
	c := NewClient(context.Background(), dial, defaultPadding(), "", 0, 0, 0, true)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	_, _ = c.CreateStream(ctx)
	cancel()
	time.Sleep(600 * time.Millisecond)
	c.sessionsLock.Lock()
	left := len(c.sessions)
	c.sessionsLock.Unlock()
	if left != 0 || idleCount(c) != 0 {
		t.Fatalf("a session finished after its request was kept: %d live, %d idle", left, idleCount(c))
	}
}
