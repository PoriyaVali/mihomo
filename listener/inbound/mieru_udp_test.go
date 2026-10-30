package inbound_test

import (
	"context"
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

// udpEchoTunnel echoes every packet and records the source each came from.
type udpEchoTunnel struct {
	mu      sync.Mutex
	sources []string
	ips     []netip.Addr
}

func (*udpEchoTunnel) HandleTCPConn(conn net.Conn, _ *C.Metadata) { _ = conn.Close() }
func (t *udpEchoTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	t.mu.Lock()
	t.sources = append(t.sources, packet.LocalAddr().String())
	t.ips = append(t.ips, metadata.SrcIP)
	t.mu.Unlock()
	_, _ = packet.WriteBack(packet.Data(), metadata.UDPAddr())
	packet.Drop()
}
func (*udpEchoTunnel) NatTable() C.NatTable { return nil }

// Every UDP association of a mieru session reads its packets as coming from
// the session's remote address. Each needs a source of its own: a NAT keyed on
// the packet source otherwise sends an association's replies to the session's
// earlier, closed association to the same destination.
func TestInboundMieruUDPAssociationsHaveTheirOwnSource(t *testing.T) {
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
				BaseOption: inbound.BaseOption{NameStr: "mieru_udp_" + transport, Listen: "127.0.0.1", Port: strconv.Itoa(port)},
				Transport:  transport,
				Users:      map[string]string{"alice": "alice-password"},
			})
			require.NoError(t, err)
			tunnel := &udpEchoTunnel{}
			require.NoError(t, in.Listen(tunnel))
			defer in.Close()
			server, err := netip.ParseAddrPort(in.Address())
			require.NoError(t, err)
			out, err := outbound.NewMieru(outbound.MieruOption{Name: "alice", Server: server.Addr().String(), Port: int(server.Port()),
				Transport: transport, UserName: "alice", Password: "alice-password", HandshakeMode: "HANDSHAKE_STANDARD"})
			require.NoError(t, err)
			defer out.Close()

			destination := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5353}
			for i := 0; i < 2; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				pc, err := out.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 5353})
				cancel()
				require.NoError(t, err)
				payload := []byte("association " + strconv.Itoa(i))
				_, err = pc.WriteTo(payload, destination)
				require.NoError(t, err)
				_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
				b := make([]byte, 64)
				n, _, err := pc.ReadFrom(b)
				require.NoError(t, err)
				assert.Equal(t, payload, b[:n])
				require.NoError(t, pc.Close())
			}
			tunnel.mu.Lock()
			defer tunnel.mu.Unlock()
			require.Len(t, tunnel.sources, 2)
			assert.NotEqual(t, tunnel.sources[0], tunnel.sources[1], "two associations shared a source")
			for _, ip := range tunnel.ips {
				assert.Equal(t, "127.0.0.1", ip.String(), "the source IP is still the client's")
			}
		})
	}
}
