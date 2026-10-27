package session

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
)

func TestStreamCloseConcurrentWithReadAndLateHook(t *testing.T) {
	for i := 0; i < 100; i++ {
		s := newStream(1, nil)
		var calls atomic.Int32
		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			_, e := s.Read(make([]byte, 1))
			if e != net.ErrClosed {
				t.Errorf("close did not wake reader: %v", e)
			}
		}()
		go func() { defer wg.Done(); s.closeLocally() }()
		go func() { defer wg.Done(); s.setDieHook(func() { calls.Add(1) }) }()
		wg.Wait()
		s.closeLocally()
		if calls.Load() != 1 {
			t.Fatalf("close hook called %d times", calls.Load())
		}
		if _, e := s.Write([]byte("closed")); e != net.ErrClosed {
			t.Fatal(e)
		}
	}
}
