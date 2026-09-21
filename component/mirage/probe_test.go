package mirage

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestProbeUsesRequestedShapeAndClosesOnCancel(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	shape := Shape{1, 2, true}
	ctx, probe := WithProbe(parent, shape)
	client, server := net.Pipe()
	defer server.Close()
	done := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, server); close(done) }()
	wrapped := WrapContext(ctx, client)
	if _, err := wrapped.Write(clientHello("example.com")); err != nil {
		t.Fatal(err)
	}
	actual, ok := probe.Applied()
	if !ok || actual != shape {
		t.Fatalf("actual=%+v applied=%v", actual, ok)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("socket survived cancellation")
	}
	probe.Close()
}

func TestProbeRejectsMultipleTLSLayersAndLateSockets(t *testing.T) {
	ctx, probe := WithProbe(context.Background(), Shape{5, 2, false})
	for i := 0; i < 2; i++ {
		a, b := net.Pipe()
		defer b.Close()
		go io.Copy(io.Discard, b)
		_, err := WrapContext(ctx, a).Write(clientHello("example.com"))
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := probe.Applied(); ok {
		t.Fatal("ambiguous nested TLS was attested")
	}
	probe.Close()
	a, b := net.Pipe()
	defer b.Close()
	if _, err := WrapContext(ctx, a).Write([]byte{1}); err == nil {
		t.Fatal("late connection survived closure")
	}
}
