package inbound

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
)

func TestShadowQuicProgrammaticDialerPreservesConfigEquality(t *testing.T) {
	a := ShadowQuicOption{BaseOption: BaseOption{NameStr: "managed"}, JLSUpstream: ShadowQuicJLSUpstream{Addr: "first.example:443"}, PacketDialer: func(context.Context, string, string) (net.PacketConn, net.Addr, error) { return nil, nil, nil }}
	encoded, e := json.Marshal(a)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(encoded), "PacketDialer") {
		t.Fatal("host callback escaped into wire config")
	}
	b := a
	b.JLSUpstream.Addr = "changed.example:443"
	if a.Equal(b) {
		t.Fatal("callback hid a changed decoy address from listener reload")
	}
	b = a
	b.PacketDialer = nil
	if !a.Equal(b) {
		t.Fatal("programmatic callback changed the serialized server configuration")
	}
}
