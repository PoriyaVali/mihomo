package socks5

import (
	"errors"
	"github.com/metacubex/mihomo/component/auth"
	"io"
	"net"
	"testing"
	"time"
)

func TestAuthenticatedAssociationReply(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(time.Second))
	_ = b.SetDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() {
		_, cmd, name, e := ServerHandshakeWithReply(a, auth.NewAuthenticator([]auth.AuthUser{{User: "alice", Pass: "secret"}}), func(cmd Command, user string, target Addr) (net.Addr, error) {
			if cmd != CmdUDPAssociate || user != "alice" || target.String() != "0.0.0.0:0" {
				return nil, errors.New("wrong authenticated association")
			}
			return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}, nil
		})
		if e == nil && (cmd != CmdUDPAssociate || name != "alice") {
			e = errors.New("lost identity")
		}
		done <- e
	}()
	bound, e := ClientHandshake(b, ParseAddr("0.0.0.0:0"), CmdUDPAssociate, &User{Username: "alice", Password: "secret"})
	if e != nil {
		t.Fatal(e)
	}
	if bound.String() != "127.0.0.1:12345" {
		t.Fatal(bound.String())
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}
func TestRejectedAssociationDoesNotSucceedOnClient(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(time.Second))
	_ = b.SetDeadline(time.Now().Add(time.Second))
	go func() {
		defer a.Close()
		_, _, _, _ = ServerHandshakeWithReply(a, auth.AlwaysValid, func(Command, string, Addr) (net.Addr, error) { return nil, errors.New("allocation denied") })
	}()
	if _, e := ClientHandshake(b, ParseAddr("0.0.0.0:0"), CmdUDPAssociate, &User{Username: "alice", Password: "secret"}); !errors.Is(e, ErrConnectionNotAllowed) {
		t.Fatalf("failure reply accepted: %v", e)
	}
}
func TestAuthenticationMethodMustBeOffered(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(time.Second))
	_ = b.SetDeadline(time.Now().Add(time.Second))
	called := make(chan bool, 1)
	go func() {
		_, _, _, _ = ServerHandshakeWithReply(a, auth.AlwaysValid, func(Command, string, Addr) (net.Addr, error) { called <- true; return nil, nil })
		close(called)
	}()
	if _, e := b.Write([]byte{5, 1, 0}); e != nil {
		t.Fatal(e)
	}
	reply := make([]byte, 2)
	if _, e := io.ReadFull(b, reply); e != nil {
		t.Fatal(e)
	}
	if reply[1] != 0xff {
		t.Fatalf("selected an unoffered method: %v", reply)
	}
	if v := <-called; v {
		t.Fatal("relay allocated without authentication")
	}
}
