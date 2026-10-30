package httpmask

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type pipeDeadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{}
}

func makePipeDeadline() pipeDeadline {
	return pipeDeadline{cancel: make(chan struct{})}
}

func (d *pipeDeadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel
	}
	d.timer = nil

	closed := isClosedPipeChan(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}

	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		d.timer = time.AfterFunc(dur, func() {
			close(d.cancel)
		})
		return
	}

	if !closed {
		close(d.cancel)
	}
}

func (d *pipeDeadline) wait() <-chan struct{} {
	d.mu.Lock()
	ch := d.cancel
	d.mu.Unlock()
	return ch
}

func isClosedPipeChan(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

type halfPipeAddr struct{}

func (halfPipeAddr) Network() string { return "pipe" }
func (halfPipeAddr) String() string  { return "pipe" }

type halfPipeConn struct {
	wrMu sync.Mutex

	rdRx <-chan []byte
	rdTx chan<- int

	wrTx chan<- []byte
	wrRx <-chan int

	readOnce  sync.Once
	writeOnce sync.Once

	localReadDone  chan struct{}
	localWriteDone chan struct{}

	remoteReadDone  <-chan struct{}
	remoteWriteDone <-chan struct{}

	readDeadline  pipeDeadline
	writeDeadline pipeDeadline

	// localAddr and remoteAddr override the pipe's own address (newTunnelPipe).
	localAddr, remoteAddr net.Addr
}

func newHalfPipe() (net.Conn, net.Conn) {
	c1, c2 := newHalfPipeConns()
	return c1, c2
}

// newTunnelPipe is a half pipe whose first end reports the addresses of the
// HTTP connection that opened the tunnel; the tunnel's later requests come
// from the same client, whose address the proxy behind it needs.
func newTunnelPipe(opener net.Conn) (net.Conn, net.Conn) {
	c1, c2 := newHalfPipeConns()
	c1.localAddr, c1.remoteAddr = opener.LocalAddr(), opener.RemoteAddr()
	return c1, c2
}

func newHalfPipeConns() (*halfPipeConn, *halfPipeConn) {
	cb1 := make(chan []byte)
	cb2 := make(chan []byte)
	cn1 := make(chan int)
	cn2 := make(chan int)

	r1 := make(chan struct{})
	w1 := make(chan struct{})
	r2 := make(chan struct{})
	w2 := make(chan struct{})

	c1 := &halfPipeConn{
		rdRx: cb1,
		rdTx: cn1,
		wrTx: cb2,
		wrRx: cn2,

		localReadDone:   r1,
		localWriteDone:  w1,
		remoteReadDone:  r2,
		remoteWriteDone: w2,

		readDeadline:  makePipeDeadline(),
		writeDeadline: makePipeDeadline(),
	}
	c2 := &halfPipeConn{
		rdRx: cb2,
		rdTx: cn2,
		wrTx: cb1,
		wrRx: cn1,

		localReadDone:   r2,
		localWriteDone:  w2,
		remoteReadDone:  r1,
		remoteWriteDone: w1,

		readDeadline:  makePipeDeadline(),
		writeDeadline: makePipeDeadline(),
	}
	return c1, c2
}

func (c *halfPipeConn) LocalAddr() net.Addr {
	if c.localAddr != nil {
		return c.localAddr
	}
	return halfPipeAddr{}
}

func (c *halfPipeConn) RemoteAddr() net.Addr {
	if c.remoteAddr != nil {
		return c.remoteAddr
	}
	return halfPipeAddr{}
}

func (c *halfPipeConn) Read(p []byte) (int, error) {
	switch {
	case isClosedPipeChan(c.localReadDone):
		return 0, io.ErrClosedPipe
	case isClosedPipeChan(c.remoteWriteDone):
		return 0, io.EOF
	case isClosedPipeChan(c.readDeadline.wait()):
		return 0, os.ErrDeadlineExceeded
	}

	select {
	case b := <-c.rdRx:
		n := copy(p, b)
		c.rdTx <- n
		return n, nil
	case <-c.localReadDone:
		return 0, io.ErrClosedPipe
	case <-c.remoteWriteDone:
		return 0, io.EOF
	case <-c.readDeadline.wait():
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *halfPipeConn) Write(p []byte) (int, error) {
	switch {
	case isClosedPipeChan(c.localWriteDone):
		return 0, io.ErrClosedPipe
	case isClosedPipeChan(c.remoteReadDone):
		return 0, io.ErrClosedPipe
	case isClosedPipeChan(c.writeDeadline.wait()):
		return 0, os.ErrDeadlineExceeded
	}

	c.wrMu.Lock()
	defer c.wrMu.Unlock()

	var (
		total int
		rest  = p
	)
	for once := true; once || len(rest) > 0; once = false {
		select {
		case c.wrTx <- rest:
			n := <-c.wrRx
			rest = rest[n:]
			total += n
		case <-c.localWriteDone:
			return total, io.ErrClosedPipe
		case <-c.remoteReadDone:
			return total, io.ErrClosedPipe
		case <-c.writeDeadline.wait():
			return total, os.ErrDeadlineExceeded
		}
	}
	return total, nil
}

func (c *halfPipeConn) CloseWrite() error {
	c.writeOnce.Do(func() { close(c.localWriteDone) })
	return nil
}

func (c *halfPipeConn) CloseRead() error {
	c.readOnce.Do(func() { close(c.localReadDone) })
	return nil
}

func (c *halfPipeConn) Close() error {
	_ = c.CloseRead()
	_ = c.CloseWrite()
	return nil
}

func (c *halfPipeConn) peerClosed() bool {
	return isClosedPipeChan(c.remoteReadDone) && isClosedPipeChan(c.remoteWriteDone)
}

func (c *halfPipeConn) SetDeadline(t time.Time) error {
	c.readDeadline.set(t)
	c.writeDeadline.set(t)
	return nil
}

func (c *halfPipeConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.set(t)
	return nil
}

func (c *halfPipeConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.set(t)
	return nil
}
