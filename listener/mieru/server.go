package mieru

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"

	mierucommon "github.com/enfein/mieru/v3/apis/common"
	mieruconstant "github.com/enfein/mieru/v3/apis/constant"
	mierumodel "github.com/enfein/mieru/v3/apis/model"
)

func Handle(conn net.Conn, tunnel C.Tunnel, request *mierumodel.Request, additions ...inbound.Addition) {
	// Return a fake response to the client.
	resp := &mierumodel.Response{
		Reply: mieruconstant.Socks5ReplySuccess,
		BindAddr: mierumodel.AddrSpec{
			IP:   net.IPv4zero,
			Port: 0,
		},
	}
	if err := resp.WriteToSocks5(conn); err != nil {
		conn.Close()
		return
	}
	user := conn.(mierucommon.UserContext).UserName()
	// Handle the connection with tunnel.
	switch request.Command {
	case mieruconstant.Socks5ConnectCmd: // TCP
		metadata := &C.Metadata{
			NetWork: C.TCP,
			Type:    C.MIERU,
			DstPort: uint16(request.DstAddr.Port),
		}
		if request.DstAddr.FQDN != "" {
			metadata.Host = request.DstAddr.FQDN
		} else if request.DstAddr.IP != nil {
			metadata.DstIP, _ = netip.AddrFromSlice(request.DstAddr.IP)
			metadata.DstIP = metadata.DstIP.Unmap()
		}
		inbound.ApplyAdditions(
			metadata,
			inbound.WithInUser(user),
			inbound.WithSrcAddr(conn.RemoteAddr()),
			inbound.WithInAddr(conn.LocalAddr()),
		)
		inbound.ApplyAdditions(metadata, additions...)
		tunnel.HandleTCPConn(conn, metadata)
	case mieruconstant.Socks5UDPAssociateCmd: // UDP
		additions = append(additions, inbound.WithInUser(user))
		pc := mierucommon.NewPacketOverStreamTunnel(conn)
		ep := N.NewEnhancePacketConn(pc)
		defer ep.Close()
		// Every association of a session reads its packets as coming from the
		// session's remote address. Name each one apart, so that a NAT keyed on
		// the packet source sends an association its own replies, not those of
		// the session's earlier association to the same destination.
		source := N.NewCustomAddr("mieru", "mieru-"+strconv.FormatUint(associations.Add(1), 10), conn.RemoteAddr())
		for {
			data, put, _, err := ep.WaitReadFrom()
			if err != nil {
				if put != nil {
					// Unresolved UDP packet, return buffer to the pool.
					put()
				}
				// mieru returns EOF or ErrUnexpectedEOF when a session is closed.
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.ErrClosedPipe) {
					break
				}
				continue
			}
			target, payload, err := socks5.DecodeUDPPacket(data)
			if err != nil {
				return
			}
			packet := &packet{
				pc:      ep,
				addr:    source,
				payload: payload,
				put:     put,
			}
			tunnel.HandleUDPPacket(inbound.NewPacket(target, packet, C.MIERU, additions...))
		}
	}
}

// associations numbers the UDP associations the listeners accept.
var associations atomic.Uint64

type packet struct {
	pc      net.PacketConn
	addr    net.Addr // the association, whose raw address is the session's remote IP & Port
	payload []byte
	put     func()
}

var _ C.UDPPacket = (*packet)(nil)
var _ C.UDPPacketInAddr = (*packet)(nil)

func (c *packet) Data() []byte {
	return c.payload
}

func (c *packet) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	packet, err := socks5.EncodeUDPPacket(socks5.ParseAddrToSocksAddr(addr), b)
	if err != nil {
		return
	}
	return c.pc.WriteTo(packet, c.addr)
}

func (c *packet) Drop() {
	if c.put != nil {
		c.put()
		c.put = nil
	}
	c.payload = nil
}

func (c *packet) LocalAddr() net.Addr {
	return c.addr
}

func (c *packet) InAddr() net.Addr {
	return c.pc.LocalAddr()
}
