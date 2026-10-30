package inbound

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/shadowquic"
	"github.com/metacubex/mihomo/log"
)

type ShadowQuicOption struct {
	PacketDialer func(context.Context, string, string) (net.PacketConn, net.Addr, error) `inbound:"-" json:"-" yaml:"-"`
	BaseOption
	Users                 []ShadowQuicUser      `inbound:"users,omitempty"`
	JLSUpstream           ShadowQuicJLSUpstream `inbound:"jls-upstream"`
	ALPN                  []string              `inbound:"alpn,omitempty"`
	QUICVersions          []string              `inbound:"quic-versions,omitempty"`
	ZeroRTT               bool                  `inbound:"zero-rtt,omitempty"`
	CongestionController  string                `inbound:"congestion-controller,omitempty"`
	Up                    string                `inbound:"up,omitempty"`
	Down                  string                `inbound:"down,omitempty"`
	IgnoreClientBandwidth bool                  `inbound:"ignore-client-bandwidth,omitempty"`
	MaxIdleTime           int                   `inbound:"max-idle-time,omitempty"`
	MaxDatagramFrameSize  int                   `inbound:"max-datagram-frame-size,omitempty"`
	ReceiveWindowConn     int                   `inbound:"recv-window-conn,omitempty"`
	ReceiveWindow         int                   `inbound:"recv-window,omitempty"`
	DisableMTUDiscovery   bool                  `inbound:"disable-mtu-discovery,omitempty"`
	CWND                  int                   `inbound:"cwnd,omitempty"`
	BBRProfile            string                `inbound:"bbr-profile,omitempty"`
	MuxOption             MuxOption             `inbound:"mux-option,omitempty"`
}

type ShadowQuicUser struct {
	Username string `inbound:"username"`
	Password string `inbound:"password"`
}

type ShadowQuicJLSUpstream struct {
	Addr      string `inbound:"addr"`
	SNI       string `inbound:"sni,omitempty"`
	Proxy     string `inbound:"proxy,omitempty"`
	RateLimit uint64 `inbound:"rate-limit,omitempty"`
}

func (u ShadowQuicUser) Build() LC.ShadowQuicUser {
	return LC.ShadowQuicUser{
		Username: u.Username,
		Password: u.Password,
	}
}

func (u ShadowQuicJLSUpstream) Build() LC.ShadowQuicJLSUpstream {
	return LC.ShadowQuicJLSUpstream{
		Addr:      u.Addr,
		SNI:       u.SNI,
		Proxy:     u.Proxy,
		RateLimit: u.RateLimit,
	}
}

func (o ShadowQuicOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type ShadowQuic struct {
	*Base
	mu     sync.Mutex
	config *ShadowQuicOption
	l      *shadowquic.Listener
	ss     LC.ShadowQuicServer
}

func NewShadowQuic(options *ShadowQuicOption) (*ShadowQuic, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &ShadowQuic{
		Base:   base,
		config: options,
		ss: LC.ShadowQuicServer{
			Enable:                true,
			PacketDialer:          options.PacketDialer,
			Listen:                base.RawAddress(),
			Users:                 utils.Map(options.Users, ShadowQuicUser.Build),
			JLSUpstream:           options.JLSUpstream.Build(),
			ALPN:                  options.ALPN,
			QUICVersions:          options.QUICVersions,
			ZeroRTT:               options.ZeroRTT,
			CongestionController:  options.CongestionController,
			Up:                    options.Up,
			Down:                  options.Down,
			IgnoreClientBandwidth: options.IgnoreClientBandwidth,
			MaxIdleTime:           options.MaxIdleTime,
			MaxDatagramFrameSize:  options.MaxDatagramFrameSize,
			ReceiveWindowConn:     options.ReceiveWindowConn,
			ReceiveWindow:         options.ReceiveWindow,
			DisableMTUDiscovery:   options.DisableMTUDiscovery,
			CWND:                  options.CWND,
			BBRProfile:            options.BBRProfile,
			MuxOption:             options.MuxOption.Build(),
		},
	}, nil
}

func (s *ShadowQuic) Config() C.InboundConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.config
}

func (s *ShadowQuic) Address() string {
	var addrList []string
	s.mu.Lock()
	l := s.l
	s.mu.Unlock()
	if l != nil {
		for _, addr := range l.AddrList() {
			addrList = append(addrList, addr.String())
		}
	}
	return strings.Join(addrList, ",")
}

func (s *ShadowQuic) Listen(tunnel C.Tunnel) error {
	s.mu.Lock()
	l, err := shadowquic.New(s.ss, s.ListenConfig(), tunnel, s.Additions()...)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.l = l
	s.mu.Unlock()
	log.Infoln("ShadowQuic[%s] proxy listening at: %s", s.Name(), s.Address())
	return nil
}

// UpdateUsers replaces the users of the running listener without closing it.
// Connections that already authenticated keep their user: an embedder removing
// a user closes that user's connections itself.
func (s *ShadowQuic) UpdateUsers(users []ShadowQuicUser) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.l == nil {
		return errors.New("shadowquic: listener is not running")
	}
	config := *s.config
	config.Users = append([]ShadowQuicUser(nil), users...)
	s.l.UpdateUsers(utils.Map(config.Users, ShadowQuicUser.Build))
	s.config = &config
	s.ss.Users = utils.Map(config.Users, ShadowQuicUser.Build)
	return nil
}

func (s *ShadowQuic) Close() error {
	s.mu.Lock()
	l := s.l
	s.mu.Unlock()
	if l != nil {
		return l.Close()
	}
	return nil
}

var _ C.InboundListener = (*ShadowQuic)(nil)
