package session

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/transport/anytls/padding"
	"github.com/metacubex/mihomo/transport/anytls/skiplist"
	"github.com/metacubex/mihomo/transport/anytls/util"
)

type Client struct {
	die       context.Context
	dieCancel context.CancelFunc

	dialOut util.DialOutFunc

	sessionCounter atomic.Uint64

	idleSession     *skiplist.SkipList[uint64, *Session]
	idleSessionLock sync.Mutex
	// idleReady is closed, and replaced, whenever a session joins the pool.
	idleReady chan struct{}

	sessions     map[uint64]*Session
	sessionsLock sync.Mutex

	padding *atomic.Pointer[padding.PaddingFactory]

	clientMetadata     string
	synRTT             synRTT
	idleSessionTimeout time.Duration
	minIdleSession     int
	disableReuse       bool
}

func NewClient(ctx context.Context, dialOut util.DialOutFunc, _padding *atomic.Pointer[padding.PaddingFactory], clientMetadata string, idleSessionCheckInterval, idleSessionTimeout time.Duration, minIdleSession int, disableReuse bool) *Client {
	c := &Client{
		sessions:           make(map[uint64]*Session),
		dialOut:            dialOut,
		padding:            _padding,
		clientMetadata:     clientMetadata,
		idleSessionTimeout: idleSessionTimeout,
		minIdleSession:     minIdleSession,
		disableReuse:       disableReuse,
	}
	if idleSessionCheckInterval <= time.Second*5 {
		idleSessionCheckInterval = time.Second * 30
	}
	if c.idleSessionTimeout <= time.Second*5 {
		c.idleSessionTimeout = time.Second * 30
	}
	c.die, c.dieCancel = context.WithCancel(ctx)
	c.idleSession = skiplist.NewSkipList[uint64, *Session]()
	c.idleReady = make(chan struct{})
	if !c.disableReuse {
		util.StartRoutine(c.die, idleSessionCheckInterval, c.idleCleanup)
	}
	return c
}

func (c *Client) CreateStream(ctx context.Context) (net.Conn, error) {
	select {
	case <-c.die.Done():
		return nil, io.ErrClosedPipe
	default:
	}

	var session *Session
	var stream *Stream
	var err error

	if !c.disableReuse {
		session = c.getIdleSession()
	}
	if session == nil {
		session, err = c.createSession(ctx)
	}
	if session == nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	stream, err = session.OpenStream()
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("failed to create stream: %w", err)
	}

	stream.setDieHook(func() {
		// If Session is not closed, put this Stream to pool
		if !session.IsClosed() {
			c.keepIdle(session)
		}
	})

	return stream, nil
}

// keepIdle puts a live session in the idle pool, or closes it when reuse is
// off or the client has been closed.
//
// Whether the session is closed is checked under the pool lock. Its close
// hook removes it from the pool under the same lock, so a session that closed
// first - a handshake finishing just as the peer drops the connection - is
// never inserted after its removal, where the next request would take it and
// fail instead of dialling a new one.
func (c *Client) keepIdle(session *Session) {
	if c.disableReuse {
		session.Close()
		return
	}
	select {
	case <-c.die.Done():
		// Now client has been closed
		session.Close()
	default:
		c.idleSessionLock.Lock()
		if session.IsClosed() {
			c.idleSessionLock.Unlock()
			return
		}
		session.idleSince = time.Now()
		c.idleSession.Insert(math.MaxUint64-session.seq, session)
		close(c.idleReady)
		c.idleReady = make(chan struct{})
		c.idleSessionLock.Unlock()
	}
}

// getIdleSession takes the newest idle session, passing over any that closed
// while its close hook has yet to remove it.
func (c *Client) getIdleSession() *Session {
	c.idleSessionLock.Lock()
	defer c.idleSessionLock.Unlock()
	return c.takeIdleLocked()
}

// idleOrReady takes the newest idle session or, when there is none, returns
// the channel closed when one joins the pool. One lock covers both: keepIdle
// replaces the channel as it pools a session, so a request that looked at the
// pool and then took the channel separately could miss a session pooled in
// between, and wait out a handshake of its own beside it.
func (c *Client) idleOrReady() (*Session, chan struct{}) {
	c.idleSessionLock.Lock()
	defer c.idleSessionLock.Unlock()
	if session := c.takeIdleLocked(); session != nil {
		return session, nil
	}
	return nil, c.idleReady
}

// takeIdleLocked is getIdleSession for a caller holding idleSessionLock.
func (c *Client) takeIdleLocked() *Session {
	for !c.idleSession.IsEmpty() {
		it := c.idleSession.Iterate()
		session := it.Value()
		c.idleSession.Remove(it.Key())
		if !session.IsClosed() {
			return session
		}
	}
	return nil
}

// sessionDialTimeout bounds a new session's dial and handshake once the
// request that started it has given up.
const sessionDialTimeout = 20 * time.Second

// detachedContext keeps a context's values but not its deadline or
// cancellation, as context.WithoutCancel does from Go 1.21.
type detachedContext struct{ context.Context }

func (detachedContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (detachedContext) Done() <-chan struct{}       { return nil }
func (detachedContext) Err() error                  { return nil }

// createSession dials a new session for a request, which may give up first:
// mihomo allows a proxy dial five seconds in all, TCP and TLS included, and
// over a weak link a handshake can take longer. Then every request started a
// handshake that was cut off at five seconds, and no session was ever made.
// The handshake now goes on after the request has given up, within
// sessionDialTimeout, and the session it makes waits in the idle pool for the
// request that follows - apps and browsers retry a failed connection.
//
// While it waits, the request also takes any session that joins the pool -
// one freed by another stream, or a handshake an earlier request gave up on -
// rather than wait for its own, which then joins the pool in turn.
//
// A request already gone when it gets here dials nothing: there is no
// handshake under way to save.
func (c *Client) createSession(ctx context.Context) (*Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var ready chan struct{} // nil, never ready, without a pool
	if !c.disableReuse {
		var idle *Session
		if idle, ready = c.idleOrReady(); idle != nil {
			return idle, nil
		}
	}
	type dialed struct {
		session *Session
		err     error
	}
	done := make(chan dialed, 1)
	go func() {
		if err := ctx.Err(); err != nil {
			done <- dialed{nil, err} // gone before its dial began
			return
		}
		dctx, cancel := context.WithTimeout(detachedContext{ctx}, sessionDialTimeout)
		defer cancel()
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			select {
			case <-c.die.Done():
				cancel()
			case <-stop:
			}
		}()
		session, err := c.dialSession(dctx)
		done <- dialed{session, err}
	}()
	poolLater := func() {
		go func() {
			if d := <-done; d.session != nil {
				c.keepIdle(d.session)
			}
		}()
	}
	for {
		select {
		case d := <-done:
			return d.session, d.err
		case <-ready:
			var idle *Session
			if idle, ready = c.idleOrReady(); idle != nil {
				poolLater()
				return idle, nil
			}
			// Another request took it; wait for the next.
		case <-ctx.Done():
			select {
			case d := <-done: // made it as the request gave up
				return d.session, d.err
			default:
			}
			poolLater()
			return nil, ctx.Err()
		}
	}
}

func (c *Client) dialSession(ctx context.Context) (*Session, error) {
	underlying, err := c.dialOut(ctx)
	if err != nil {
		return nil, err
	}

	session := NewClientSession(underlying, c.padding, c.clientMetadata)
	session.seq = c.sessionCounter.Add(1)
	session.synRTT = &c.synRTT
	session.dieHook = func() {
		if !c.disableReuse {
			c.idleSessionLock.Lock()
			c.idleSession.Remove(math.MaxUint64 - session.seq)
			c.idleSessionLock.Unlock()
		}

		c.sessionsLock.Lock()
		delete(c.sessions, session.seq)
		c.sessionsLock.Unlock()
	}

	c.sessionsLock.Lock()
	c.sessions[session.seq] = session
	c.sessionsLock.Unlock()

	session.Run()
	return session, nil
}

func (c *Client) Close() error {
	c.dieCancel()

	c.sessionsLock.Lock()
	sessionToClose := make([]*Session, 0, len(c.sessions))
	for _, session := range c.sessions {
		sessionToClose = append(sessionToClose, session)
	}
	c.sessions = make(map[uint64]*Session)
	c.sessionsLock.Unlock()

	for _, session := range sessionToClose {
		session.Close()
	}

	return nil
}

func (c *Client) idleCleanup() {
	c.idleCleanupExpTime(time.Now().Add(-c.idleSessionTimeout))
}

func (c *Client) idleCleanupExpTime(expTime time.Time) {
	activeCount := 0

	c.idleSessionLock.Lock()
	sessionToClose := make([]*Session, 0, c.idleSession.Len())

	it := c.idleSession.Iterate()
	for it.IsNotEnd() {
		session := it.Value()
		key := it.Key()
		it.MoveToNext()

		if !session.idleSince.Before(expTime) {
			activeCount++
			continue
		}

		if activeCount < c.minIdleSession {
			session.idleSince = time.Now()
			activeCount++
			continue
		}

		sessionToClose = append(sessionToClose, session)
		c.idleSession.Remove(key)
	}
	c.idleSessionLock.Unlock()

	for _, session := range sessionToClose {
		session.Close()
	}
}
