package inbound_test

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/shadowtls"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shadowTLSEchoTunnel serves the ShadowTLS handshake server and echoes every
// other stream, recording the user that opened it.
type shadowTLSEchoTunnel struct{ echoTunnel }

func (t *shadowTLSEchoTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	if metadata.Type != C.INNER {
		t.echoTunnel.HandleTCPConn(conn, metadata)
		return
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tls.Server(conn, tlsConfig).HandshakeContext(ctx); err == nil {
		_, _ = io.Copy(io.Discard, conn)
	}
}

func startSnellUsers(t *testing.T, option inbound.SnellOption) (*inbound.Snell, *shadowTLSEchoTunnel, netip.AddrPort) {
	option.BaseOption = inbound.BaseOption{NameStr: "snell_users", Listen: "127.0.0.1", Port: "0"}
	option.ShadowTLS = inbound.ShadowTLS{Enable: true, Version: 3, StrictMode: true,
		Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")}}
	in, err := inbound.NewSnell(&option)
	require.NoError(t, err)
	tunnel := &shadowTLSEchoTunnel{}
	require.NoError(t, in.Listen(tunnel))
	t.Cleanup(func() { _ = in.Close() })
	server, err := netip.ParseAddrPort(in.Address())
	require.NoError(t, err)
	return in, tunnel, server
}

// snellUserClient connects with one secret as both the Snell PSK and the
// ShadowTLS password, as a managed node's subscription does.
func snellUserClient(t *testing.T, server netip.AddrPort, version int, reuse bool, secret string) echoDialer {
	out, err := outbound.NewSnell(outbound.SnellOption{Name: "snell_user", Server: server.Addr().String(), Port: int(server.Port()),
		Psk: secret, Version: version, Reuse: reuse,
		ObfsOpts: map[string]any{"mode": shadowtls.Mode, "host": realityDest, "password": secret, "fingerprint": tlsFingerprint, "version": 3}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })
	return out
}

func TestInboundSnellUpdateUsersKeepsOtherSessions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version int
		reuse   bool
	}{{"v3", 3, false}, {"v4-reuse", 4, true}, {"v5", 5, false}} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in, tunnel, server := startSnellUsers(t, inbound.SnellOption{Version: tc.version,
				Users: map[string]string{"alice": "alice-password", "bob": "bob-password"}})
			testUpdateUsers(t, &tunnel.echoTunnel, func(user, password string) echoDialer {
				return snellUserClient(t, server, tc.version, tc.reuse, password)
			}, in.UpdateUsers)
			assert.Equal(t, 2, len(in.Config().(*inbound.SnellOption).Users))
		})
	}
}

func TestInboundSnellUsersNeedTheirOwnPSK(t *testing.T) {
	t.Parallel()
	_, tunnel, server := startSnellUsers(t, inbound.SnellOption{Users: map[string]string{"alice": "alice-password", "bob": "bob-password"}})

	// Bob's ShadowTLS password with Alice's PSK: the handshake names bob,
	// whose PSK does not open the stream.
	out, err := outbound.NewSnell(outbound.SnellOption{Name: "mixed", Server: server.Addr().String(), Port: int(server.Port()), Psk: "alice-password",
		ObfsOpts: map[string]any{"mode": shadowtls.Mode, "host": realityDest, "password": "bob-password", "fingerprint": tlsFingerprint, "version": 3}})
	require.NoError(t, err)
	defer out.Close()
	if conn, err := openEcho(out); err == nil {
		assert.Error(t, echoOnce(conn, "mixed"))
		_ = conn.Close()
	}
	assert.Empty(t, tunnel.seen())

	conn, err := openEcho(snellUserClient(t, server, 4, false, "bob-password"))
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, echoOnce(conn, "bob"))
	assert.Equal(t, []string{"bob"}, tunnel.seen())
}

func TestInboundSnellUsersOptions(t *testing.T) {
	base := inbound.BaseOption{NameStr: "snell_options", Listen: "127.0.0.1", Port: "0"}
	in, err := inbound.NewSnell(&inbound.SnellOption{BaseOption: base, Users: map[string]string{"alice": "alice-password"}})
	require.NoError(t, err)
	assert.ErrorContains(t, in.Listen(&echoTunnel{}), "shadow-tls version 3", "users need ShadowTLS v3 to tell them apart")

	snellIn, _, _ := startSnellUsers(t, inbound.SnellOption{Users: map[string]string{"alice": "alice-password"}})
	assert.Error(t, snellIn.UpdateUsers(map[string]string{}), "an empty user table is rejected")
	assert.Error(t, snellIn.UpdateUsers(map[string]string{"alice": "same", "twin": "same"}), "two users cannot share a PSK")
	assert.Equal(t, map[string]string{"alice": "alice-password"}, snellIn.Config().(*inbound.SnellOption).Users)

	single, err := inbound.NewSnell(&inbound.SnellOption{BaseOption: base, Psk: "shared"})
	require.NoError(t, err)
	require.NoError(t, single.Listen(&echoTunnel{}))
	defer single.Close()
	assert.Error(t, single.UpdateUsers(map[string]string{"alice": "alice-password"}), "a single-PSK inbound has no users")
}
