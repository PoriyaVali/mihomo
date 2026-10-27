package smux

import (
	"bytes"
	"testing"
	"time"
)

func TestQueuedWriteOwnsPayloadAfterTimeout(t *testing.T) {
	s := &Session{shaper: make(chan writeRequest), die: make(chan struct{}), chSocketWriteError: make(chan struct{})}
	deadline := make(chan time.Time)
	source := []byte("owned payload")
	done := make(chan error, 1)
	go func() { _, e := s.writeFrameInternal(Frame{data: source}, deadline, CLSDATA); done <- e }()
	queued := <-s.shaper
	close(deadline)
	if e := <-done; e != ErrTimeout {
		t.Fatalf("expected write timeout, got %v", e)
	}
	// A net.Conn caller may reuse its slice as soon as Write returns, even
	// though the asynchronously queued request has not been sent yet.
	for i := range source {
		source[i] = 'X'
	}
	if !bytes.Equal(queued.frame.data, []byte("owned payload")) {
		t.Fatalf("queued data changed after Write returned: %q", queued.frame.data)
	}
}
