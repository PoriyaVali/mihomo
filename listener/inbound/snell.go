package inbound

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/snell"
	"github.com/metacubex/mihomo/log"
)

type SnellOption struct {
	BaseOption
	Psk       string          `inbound:"psk"`
	Version   int             `inbound:"version,omitempty"`
	UDP       bool            `inbound:"udp,omitempty"`
	ObfsOpts  SnellObfsOption `inbound:"obfs-opts,omitempty"`
	ShadowTLS ShadowTLS       `inbound:"shadow-tls,omitempty"`
	ResTLS    ResTLS          `inbound:"res-tls,omitempty"`
	JLSConfig JLSConfig       `inbound:"jls-config,omitempty"`
	// Users, when set, gives each user (name -> PSK) its own key and requires
	// ShadowTLS version 3, whose handshake names the user: a user's PSK is
	// also their ShadowTLS password. Psk and ShadowTLS users are then unused.
	Users map[string]string `inbound:"users,omitempty"`
}

func (o SnellOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type SnellObfsOption struct {
	Mode string `obfs:"mode,omitempty"`
	Host string `obfs:"host,omitempty"`
}

type Snell struct {
	*Base
	mu     sync.Mutex
	config *SnellOption
	l      *snell.Listener
	snell  LC.SnellServer
}

func NewSnell(options *SnellOption) (*Snell, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	if options.Version == 0 {
		options.Version = 4
	}
	if options.Version < 1 || options.Version > 5 {
		return nil, fmt.Errorf("snell inbound version %d is not supported", options.Version)
	}

	return &Snell{
		Base:   base,
		config: options,
		snell: LC.SnellServer{
			Listen:    base.RawAddress(),
			Psk:       options.Psk,
			Version:   options.Version,
			UDP:       options.UDP,
			ObfsMode:  options.ObfsOpts.Mode,
			ObfsHost:  options.ObfsOpts.Host,
			ShadowTLS: options.ShadowTLS.Build(),
			Users:     copyUsers(options.Users),
			ResTLS:    options.ResTLS.Build(),
			JLSConfig: options.JLSConfig.Build(),
		},
	}, nil
}

func (s *Snell) Config() C.InboundConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.config
}

func (s *Snell) Address() string {
	var addrList []string
	if s.l != nil {
		for _, addr := range s.l.AddrList() {
			addrList = append(addrList, addr.String())
		}
	}
	return strings.Join(addrList, ",")
}

func (s *Snell) Listen(tunnel C.Tunnel) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, err := snell.New(s.snell, s.ListenConfig(), tunnel, s.Additions()...)
	if err != nil {
		return err
	}
	s.l = l
	log.Infoln("Snell[%s] inbound listening at: %s", s.Name(), s.Address())
	return nil
}

// UpdateUsers replaces the users of an inbound started with users, without
// closing it. Connections that already passed the handshake keep running: an
// embedder removing a user closes that user's connections itself.
func (s *Snell) UpdateUsers(users map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.l == nil {
		return errors.New("snell inbound is not listening")
	}
	if err := s.l.SetUsers(users); err != nil {
		return err
	}
	option := *s.config
	option.Users = copyUsers(users)
	s.config = &option
	s.snell.Users = option.Users
	return nil
}

func (s *Snell) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.l == nil {
		return nil
	}
	return s.l.Close()
}

var _ C.InboundListener = (*Snell)(nil)
