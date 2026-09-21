package mirage

import (
	"context"
	"net"
	"sync"
)

type Shape struct {
	Offset   int  `json:"offset"`
	Records  int  `json:"records"`
	Coalesce bool `json:"coalesce"`
}

func (s Shape) Valid() bool {
	return s.Offset >= 1 && s.Offset <= 1024 && s.Records >= 2 && s.Records <= 8
}

type probeKey struct{}

// Probe owns only isolated probe transports. Live sessions/global defaults are
// never modified. Cancellation closes the underlying sockets, not just a timer.
type Probe struct {
	mu     sync.Mutex
	shape  Shape
	conns  []*Conn
	closed bool
}

func WithProbe(ctx context.Context, shape Shape) (context.Context, *Probe) {
	p := &Probe{shape: shape}
	context.AfterFunc(ctx, p.Close)
	return context.WithValue(ctx, probeKey{}, p), p
}

func WrapContext(ctx context.Context, conn net.Conn) net.Conn {
	p, ok := ctx.Value(probeKey{}).(*Probe)
	if !ok {
		return Wrap(conn)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || !p.shape.Valid() {
		_ = conn.Close()
		return conn
	}
	wrapped := NewConnWithOptions(conn, p.shape.Offset, p.shape.Records, p.shape.Coalesce)
	p.conns = append(p.conns, wrapped)
	return wrapped
}

func (p *Probe) Applied() (Shape, bool) {
	p.mu.Lock()
	if len(p.conns) != 1 {
		p.mu.Unlock()
		return Shape{}, false
	}
	conn := p.conns[0]
	p.mu.Unlock()
	offset, records, coalesce, ok := conn.AppliedShape()
	shape := Shape{offset, records, coalesce}
	return shape, ok && shape == p.shape
}

func (p *Probe) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	for _, conn := range p.conns {
		_ = conn.Close()
	}
}
