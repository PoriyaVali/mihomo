package session

import (
	"context"
	"io"
	"math"
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

// A request waiting on its own slow handshake takes a session that joins the
// pool meanwhile: an app's retry gets the handshake its first attempt gave up
// on as soon as it lands, not one of its own begun later.
func TestWaitingRequestTakesASessionFromThePool(t *testing.T) {
	dial, dials := slowDial(t, 400*time.Millisecond)
	c := NewClient(context.Background(), dial, defaultPadding(), "", 0, 0, 0, false)
	defer c.Close()

	// The first attempt gives up at 100 ms; its handshake lands at 400 ms.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, _ = c.CreateStream(ctx)
	cancel()

	// The retry, at 150 ms, begins a handshake that would land at 550 ms.
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	st, err := c.CreateStream(ctx2)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if took := time.Since(start); took > 350*time.Millisecond {
		t.Fatalf("the retry waited %v, for a handshake of its own", took)
	}
	// Its own handshake is not wasted: it joins the pool too.
	deadline := time.Now().Add(2 * time.Second)
	for idleCount(c) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("%d sessions idle, want both handshakes kept", idleCount(c))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := dials.Load(); n != 2 {
		t.Fatalf("dialled %d times, want 2", n)
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

// A session that closed before it reached the pool - a handshake finishing
// just as the peer drops the connection - must not be pooled after its close
// hook ran: the next request would take it and fail instead of dialling.
func TestClosedSessionIsNotPooled(t *testing.T) {
	dial, dials := slowDial(t, 0)
	c := NewClient(context.Background(), dial, defaultPadding(), "", 0, 0, 0, false)
	defer c.Close()

	session, err := c.dialSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	session.Close()
	c.keepIdle(session)
	if n := idleCount(c); n != 0 {
		t.Fatalf("%d closed session(s) pooled", n)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	st, err := c.CreateStream(ctx)
	if err != nil {
		t.Fatalf("the next request failed instead of dialling: %v", err)
	}
	st.Close()
	if n := dials.Load(); n != 2 {
		t.Fatalf("dialled %d times, want a new session for the next request", n)
	}
}

// A pooled session that closed while its close hook has yet to remove it is
// passed over, not handed to a request.
func TestIdleSessionClosedInThePoolIsSkipped(t *testing.T) {
	dial, _ := slowDial(t, 0)
	c := NewClient(context.Background(), dial, defaultPadding(), "", 0, 0, 0, false)
	defer c.Close()

	conn, err := dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	session := NewClientSession(conn, defaultPadding(), "")
	session.seq = c.sessionCounter.Add(1)
	c.idleSessionLock.Lock()
	c.idleSession.Insert(math.MaxUint64-session.seq, session)
	c.idleSessionLock.Unlock()
	session.Close() // no hook: still in the pool, as in the window before it runs

	if got := c.getIdleSession(); got != nil {
		t.Fatal("a closed session was taken from the pool")
	}
}

// A request already cancelled when it reaches the dial starts none. There is
// no handshake under way to save, and one begun for nobody holds a socket
// and a TLS handshake for up to sessionDialTimeout, for every expired request
// (Codex review of PoriyaVali/hiddify-sing-box#2, whose client is this one).
func TestCancelledRequestDialsNothing(t *testing.T) {
	dial, dials := slowDial(t, 50*time.Millisecond)
	c := NewClient(context.Background(), dial, defaultPadding(), "", 0, 0, 0, false)
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.CreateStream(ctx); err == nil {
		t.Fatal("a cancelled request got a stream")
	}
	time.Sleep(200 * time.Millisecond)
	if n := dials.Load(); n != 0 {
		t.Fatalf("dialled %d times for a request that was already cancelled", n)
	}
	if n := idleCount(c); n != 0 {
		t.Fatalf("%d session(s) pooled that no request asked for", n)
	}
}

// A session pooled after the request found the pool empty, but before it
// began waiting for the pool, is taken at once. The pool's notification for
// it had already fired, so the request waited out a handshake of its own
// with a session sitting idle (Codex review of hiddify-sing-box#2).
func TestSessionPooledBeforeTheWaitIsTaken(t *testing.T) {
	fast, _ := slowDial(t, 0)
	slow, _ := slowDial(t, 2*time.Second)
	var calls atomic.Int32
	c := NewClient(context.Background(), func(ctx context.Context) (net.Conn, error) {
		if calls.Add(1) == 1 {
			return fast(ctx)
		}
		return slow(ctx)
	}, defaultPadding(), "", 0, 0, 0, false)
	defer c.Close()

	// CreateStream has found the pool empty; then a stream ends and its
	// session joins the pool.
	pooled, err := c.dialSession(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c.keepIdle(pooled)

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := c.createSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 500*time.Millisecond {
		t.Fatalf("the request waited %v with a session in the pool", took)
	}
	if got != pooled {
		t.Fatal("the request did not get the pooled session")
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("dialled %d times, want no handshake begun beside the pooled session", n)
	}
}
