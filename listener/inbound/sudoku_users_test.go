package inbound_test

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/transport/sudoku/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sudokuUserKeys splits one master key into a key per user.
func sudokuUserKeys(t *testing.T, names ...string) (string, map[string]string) {
	pair, err := crypto.GenerateMasterKey()
	require.NoError(t, err)
	keys := make(map[string]string, len(names))
	for _, name := range names {
		keys[name], err = crypto.SplitPrivateKey(pair.Private)
		require.NoError(t, err)
	}
	return crypto.EncodePoint(pair.Public), keys
}

func startSudokuUsers(t *testing.T, option inbound.SudokuOption) (*inbound.Sudoku, *echoTunnel, netip.AddrPort) {
	option.BaseOption = inbound.BaseOption{NameStr: "sudoku_users", Listen: "127.0.0.1", Port: "0"}
	in, err := inbound.NewSudoku(&option)
	require.NoError(t, err)
	tunnel := &echoTunnel{}
	require.NoError(t, in.Listen(tunnel))
	t.Cleanup(func() { _ = in.Close() })
	server, err := netip.ParseAddrPort(in.Address())
	require.NoError(t, err)
	return in, tunnel, server
}

func sudokuClient(t *testing.T, server netip.AddrPort, option outbound.SudokuOption) echoDialer {
	option.Name = "sudoku_user"
	option.Server = server.Addr().String()
	option.Port = int(server.Port())
	out, err := outbound.NewSudoku(option)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })
	return out
}

func TestInboundSudokuUpdateUsersKeepsOtherSessions(t *testing.T) {
	t.Parallel()
	public, keys := sudokuUserKeys(t, "alice", "bob", "carol")
	in, tunnel, server := startSudokuUsers(t, inbound.SudokuOption{Key: public,
		Users: map[string]string{"alice": keys["alice"], "bob": keys["bob"]}})

	// testUpdateUsers names users and passwords; here a password is the
	// user's split key.
	byPassword := map[string]string{"alice-password": keys["alice"], "bob-password": keys["bob"], "carol-password": keys["carol"]}
	testUpdateUsers(t, tunnel, func(user, password string) echoDialer {
		return sudokuClient(t, server, outbound.SudokuOption{Key: byPassword[password]})
	}, func(users map[string]string) error {
		named := make(map[string]string, len(users))
		for name, password := range users {
			named[name] = byPassword[password]
		}
		return in.UpdateUsers(named)
	})
	assert.Equal(t, 2, len(in.Config().(*inbound.SudokuOption).Users))
}

// Every HTTP mask mode and session mux attributes a connection to the user
// whose key opened it and to the client's address, and refuses a key of the
// same master that is not listed.
func TestInboundSudokuUsersAttribution(t *testing.T) {
	httpMask := true
	cases := []struct {
		name      string
		in        inbound.SudokuOption
		out       outbound.SudokuOption
		multiplex string
	}{
		{name: "legacy"},
		{name: "no-mask", in: inbound.SudokuOption{DisableHTTPMask: true}, out: outbound.SudokuOption{HTTPMask: new(bool)}},
		{name: "mux", multiplex: "on"},
		{name: "auto", in: inbound.SudokuOption{HTTPMaskMode: "auto"}, out: outbound.SudokuOption{HTTPMask: &httpMask, HTTPMaskMode: "auto"}},
		{name: "stream-mux", in: inbound.SudokuOption{HTTPMaskMode: "stream"}, out: outbound.SudokuOption{HTTPMask: &httpMask, HTTPMaskMode: "stream"}, multiplex: "on"},
		{name: "stream", in: inbound.SudokuOption{HTTPMaskMode: "stream"}, out: outbound.SudokuOption{HTTPMask: &httpMask, HTTPMaskMode: "stream"}},
		{name: "poll", in: inbound.SudokuOption{HTTPMaskMode: "poll"}, out: outbound.SudokuOption{HTTPMask: &httpMask, HTTPMaskMode: "poll"}},
		{name: "ws", in: inbound.SudokuOption{HTTPMaskMode: "ws"}, out: outbound.SudokuOption{HTTPMask: &httpMask, HTTPMaskMode: "ws"}},
		{name: "ws-mux", in: inbound.SudokuOption{HTTPMaskMode: "ws"}, out: outbound.SudokuOption{HTTPMask: &httpMask, HTTPMaskMode: "ws"}, multiplex: "on"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			public, keys := sudokuUserKeys(t, "alice", "bob", "mallory")
			option := tc.in
			option.Key = public
			option.Users = map[string]string{"alice": keys["alice"], "bob": keys["bob"]}
			_, tunnel, server := startSudokuUsers(t, option)

			for _, name := range []string{"alice", "bob"} {
				client := tc.out
				client.Key = keys[name]
				client.Multiplex = tc.multiplex
				conn, err := openEcho(sudokuClient(t, server, client))
				require.NoError(t, err, name)
				require.NoError(t, echoOnce(conn, "hello "+name), name)
				_ = conn.Close()
			}
			assert.ElementsMatch(t, []string{"alice", "bob"}, tunnel.seen())
			// The proxy sees the client's address, which a device limit counts,
			// through HTTP tunnels and mux streams too.
			for _, source := range tunnel.seenFrom() {
				assert.Equal(t, "127.0.0.1", source.String())
			}

			for _, key := range []string{keys["mallory"], public} {
				client := tc.out
				client.Key = key
				client.Multiplex = tc.multiplex
				if conn, err := openEcho(sudokuClient(t, server, client)); err == nil {
					assert.Error(t, echoOnce(conn, "unlisted"), "a key that is not listed must not open a session")
					_ = conn.Close()
				}
			}
			assert.ElementsMatch(t, []string{"alice", "bob"}, tunnel.seen())
		})
	}
}

func TestInboundSudokuUsersRejectsForeignKeys(t *testing.T) {
	public, keys := sudokuUserKeys(t, "alice")
	_, other := sudokuUserKeys(t, "eve")
	_, err := inbound.NewSudoku(&inbound.SudokuOption{BaseOption: inbound.BaseOption{NameStr: "sudoku_foreign", Listen: "127.0.0.1", Port: "0"},
		Key: public, Users: map[string]string{"alice": keys["alice"], "eve": other["eve"]}})
	assert.ErrorContains(t, err, `"eve"`)

	in, _, _ := startSudokuUsers(t, inbound.SudokuOption{Key: public, Users: map[string]string{"alice": keys["alice"]}})
	assert.Error(t, in.UpdateUsers(map[string]string{"alice": keys["alice"], "eve": other["eve"]}))
	assert.Error(t, in.UpdateUsers(map[string]string{"alice": keys["alice"], "twin": keys["alice"]}), "two users cannot share a key")
	assert.Equal(t, map[string]string{"alice": keys["alice"]}, in.Config().(*inbound.SudokuOption).Users)
}
