package inbound_test

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// echoTunnel echoes every TCP stream and records which user opened it.
type echoTunnel struct {
	mu    sync.Mutex
	users []string
}

func (t *echoTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	t.mu.Lock()
	t.users = append(t.users, metadata.InUser)
	t.mu.Unlock()
	defer conn.Close()
	_, _ = io.Copy(conn, conn)
}
func (*echoTunnel) HandleUDPPacket(packet C.UDPPacket, _ *C.Metadata) { packet.Drop() }
func (*echoTunnel) NatTable() C.NatTable                              { return nil }

func (t *echoTunnel) seen() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.users...)
}

type echoDialer interface {
	DialContext(context.Context, *C.Metadata) (C.Conn, error)
}

func openEcho(out echoDialer) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return out.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "echo.test", DstPort: 80})
}

func echoOnce(conn net.Conn, payload string) error {
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		return err
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if string(reply) != payload {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// testUpdateUsers starts with alice and bob, replaces them with alice and
// carol, and checks that alice keeps working while bob can no longer start a
// session and carol can.
func testUpdateUsers(t *testing.T, tunnel *echoTunnel, client func(user, password string) echoDialer, update func(users map[string]string) error) {
	alice := client("alice", "alice-password")
	kept, err := openEcho(alice)
	require.NoError(t, err)
	defer kept.Close()
	require.NoError(t, echoOnce(kept, "before"))

	require.NoError(t, update(map[string]string{"alice": "alice-password", "carol": "carol-password"}))

	// Alice's established stream, her new streams and a new client of hers
	// survive the update.
	require.NoError(t, echoOnce(kept, "after"))
	again, err := openEcho(alice)
	require.NoError(t, err)
	defer again.Close()
	require.NoError(t, echoOnce(again, "new stream"))
	fresh, err := openEcho(client("alice", "alice-password"))
	require.NoError(t, err)
	defer fresh.Close()
	require.NoError(t, echoOnce(fresh, "new session"))

	// A fresh client authenticates against the new table.
	if conn, err := openEcho(client("bob", "bob-password")); err == nil {
		assert.Error(t, echoOnce(conn, "removed"), "a removed user must not authenticate a new session")
		_ = conn.Close()
	}
	carol, err := openEcho(client("carol", "carol-password"))
	require.NoError(t, err)
	defer carol.Close()
	require.NoError(t, echoOnce(carol, "added"))

	assert.NotContains(t, tunnel.seen(), "bob")
	assert.Contains(t, tunnel.seen(), "carol")
}

func TestInboundMieruUpdateUsersKeepsOtherSessions(t *testing.T) {
	for _, transport := range []string{"TCP", "UDP"} {
		transport := transport
		t.Run(transport, func(t *testing.T) {
			t.Parallel()
			var port int
			if transport == "TCP" {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				port = l.Addr().(*net.TCPAddr).Port
				require.NoError(t, l.Close())
			} else {
				l, err := net.ListenPacket("udp", "127.0.0.1:0")
				require.NoError(t, err)
				port = l.LocalAddr().(*net.UDPAddr).Port
				require.NoError(t, l.Close())
			}
			in, err := inbound.NewMieru(&inbound.MieruOption{
				BaseOption: inbound.BaseOption{NameStr: "mieru_users_" + transport, Listen: "127.0.0.1", Port: strconv.Itoa(port)},
				Transport:  transport,
				Users:      map[string]string{"alice": "alice-password", "bob": "bob-password"},
			})
			require.NoError(t, err)
			tunnel := &echoTunnel{}
			require.NoError(t, in.Listen(tunnel))
			defer in.Close()
			server, err := netip.ParseAddrPort(in.Address())
			require.NoError(t, err)

			require.Error(t, in.UpdateUsers(map[string]string{}), "an empty user table is rejected")
			testUpdateUsers(t, tunnel, func(user, password string) echoDialer {
				out, err := outbound.NewMieru(outbound.MieruOption{Name: user, Server: server.Addr().String(), Port: int(server.Port()),
					Transport: transport, UserName: user, Password: password, HandshakeMode: "HANDSHAKE_STANDARD"})
				require.NoError(t, err)
				t.Cleanup(func() { _ = out.Close() })
				return out
			}, in.UpdateUsers)
		})
	}
}

func TestInboundShadowQuicUpdateUsersKeepsOtherSessions(t *testing.T) {
	t.Parallel()
	in, err := inbound.NewShadowQuic(&inbound.ShadowQuicOption{
		BaseOption:  inbound.BaseOption{NameStr: "shadowquic_users", Listen: "127.0.0.1", Port: "0"},
		ALPN:        []string{"h3"},
		Users:       []inbound.ShadowQuicUser{{Username: "alice", Password: "alice-password"}, {Username: "bob", Password: "bob-password"}},
		JLSUpstream: inbound.ShadowQuicJLSUpstream{Addr: "127.0.0.1:1"},
	})
	require.NoError(t, err)
	require.Error(t, in.UpdateUsers(nil), "a listener that is not running has no users to replace")
	tunnel := &echoTunnel{}
	require.NoError(t, in.Listen(tunnel))
	defer in.Close()
	server, err := netip.ParseAddrPort(in.Address())
	require.NoError(t, err)

	testUpdateUsers(t, tunnel, func(user, password string) echoDialer {
		out, err := outbound.NewShadowQuic(outbound.ShadowQuicOption{Name: user, Server: server.Addr().String(), Port: int(server.Port()),
			ALPN: []string{"h3"}, Username: user, Password: password})
		require.NoError(t, err)
		t.Cleanup(func() { _ = out.Close() })
		return out
	}, func(users map[string]string) error {
		var list []inbound.ShadowQuicUser
		for name, password := range users {
			list = append(list, inbound.ShadowQuicUser{Username: name, Password: password})
		}
		return in.UpdateUsers(list)
	})
	assert.Equal(t, 2, len(in.Config().(*inbound.ShadowQuicOption).Users))
}
