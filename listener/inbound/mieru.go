package inbound

import (
	"fmt"
	"sync"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/mieru"
	"github.com/metacubex/mihomo/log"
	"google.golang.org/protobuf/proto"

	mieruserver "github.com/enfein/mieru/v3/apis/server"
	mierutp "github.com/enfein/mieru/v3/apis/trafficpattern"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
)

type Mieru struct {
	*Base
	option *MieruOption
	server *mieru.Server
	mu     sync.Mutex
}

type MieruOption struct {
	BaseOption
	Transport           string            `inbound:"transport"`
	Users               map[string]string `inbound:"users"`
	TrafficPattern      string            `inbound:"traffic-pattern,omitempty"`
	UserHintIsMandatory bool              `inbound:"user-hint-is-mandatory,omitempty"`
}

func NewMieru(option *MieruOption) (*Mieru, error) {
	base, err := NewBase(&option.BaseOption)
	if err != nil {
		return nil, err
	}

	config, err := buildMieruServerConfig(option, base.ports)
	if err != nil {
		return nil, fmt.Errorf("failed to build mieru server config: %w", err)
	}
	s, err := mieru.NewServer(config)
	if err != nil {
		return nil, fmt.Errorf("failed to store mieru server config: %w", err)
	}
	// Server is started lazily when Listen() is called for the first time.
	return &Mieru{
		Base:   base,
		option: option,
		server: s,
	}, nil
}

func (m *Mieru) Config() C.InboundConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.option
}

func (m *Mieru) Listen(tunnel C.Tunnel) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.server.IsRunning() {
		if err := m.server.Start(); err != nil {
			return fmt.Errorf("failed to start mieru server: %w", err)
		}
	}

	additions := m.config.Additions()
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-MIERU"),
			inbound.WithSpecialRules(""),
		}
	}

	go func() {
		for {
			c, req, err := m.server.Accept()
			if err != nil {
				if !m.server.IsRunning() {
					break
				} else {
					continue
				}
			}
			go mieru.Handle(c, tunnel, req, additions...)
		}
	}()
	log.Infoln("Mieru[%s] proxy listening at: %s", m.Name(), m.Address())
	return nil
}

// UpdateUsers replaces the users of the listener without closing it. Sessions
// that already authenticated keep their credential: an embedder removing a
// user closes that user's connections itself.
func (m *Mieru) UpdateUsers(users map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	option := *m.option
	option.Users = make(map[string]string, len(users))
	for name, password := range users {
		option.Users[name] = password
	}
	if err := validateMieruOption(&option); err != nil {
		return fmt.Errorf("failed to validate mieru option: %w", err)
	}
	if err := m.server.SetUsers(mieruUsers(users)); err != nil {
		return fmt.Errorf("failed to update mieru users: %w", err)
	}
	m.option = &option
	return nil
}

func (m *Mieru) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.server.IsRunning() {
		return m.server.Stop()
	}

	return nil
}

var _ C.InboundListener = (*Mieru)(nil)

func (o MieruOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

func buildMieruServerConfig(option *MieruOption, ports utils.IntRanges[uint16]) (*mieruserver.ServerConfig, error) {
	if err := validateMieruOption(option); err != nil {
		return nil, fmt.Errorf("failed to validate mieru option: %w", err)
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("port is not set")
	}

	var transportProtocol *mierupb.TransportProtocol
	switch option.Transport {
	case "TCP":
		transportProtocol = mierupb.TransportProtocol_TCP.Enum()
	case "UDP":
		transportProtocol = mierupb.TransportProtocol_UDP.Enum()
	}
	var portBindings []*mierupb.PortBinding
	for _, portRange := range ports {
		if portRange.Start() == portRange.End() {
			portBindings = append(portBindings, &mierupb.PortBinding{
				Port:     proto.Int32(int32(portRange.Start())),
				Protocol: transportProtocol,
			})
		} else {
			portBindings = append(portBindings, &mierupb.PortBinding{
				PortRange: proto.String(fmt.Sprintf("%d-%d", portRange.Start(), portRange.End())),
				Protocol:  transportProtocol,
			})
		}
	}
	users := mieruUsers(option.Users)
	var trafficPattern *mierupb.TrafficPattern
	trafficPattern, _ = mierutp.Decode(option.TrafficPattern)
	var advancedSettings *mierupb.ServerAdvancedSettings
	if option.UserHintIsMandatory {
		advancedSettings = &mierupb.ServerAdvancedSettings{
			UserHintIsMandatory: proto.Bool(true),
		}
	}
	lc := option.ListenConfig()
	return &mieruserver.ServerConfig{
		Config: &mierupb.ServerConfig{
			ListenIPAddress:  proto.String(option.Listen),
			PortBindings:     portBindings,
			Users:            users,
			TrafficPattern:   trafficPattern,
			AdvancedSettings: advancedSettings,
		},
		StreamListenerFactory: lc,
		PacketListenerFactory: lc,
	}, nil
}

func mieruUsers(option map[string]string) []*mierupb.User {
	var users []*mierupb.User
	for username, password := range option {
		users = append(users, &mierupb.User{
			Name:     proto.String(username),
			Password: proto.String(password),
		})
	}
	return users
}

func validateMieruOption(option *MieruOption) error {
	if option.Transport != "TCP" && option.Transport != "UDP" {
		return fmt.Errorf("transport must be TCP or UDP")
	}
	if len(option.Users) == 0 {
		return fmt.Errorf("users is empty")
	}
	for username, password := range option.Users {
		if username == "" {
			return fmt.Errorf("username is empty")
		}
		if password == "" {
			return fmt.Errorf("password is empty")
		}
	}
	if option.TrafficPattern != "" {
		trafficPattern, err := mierutp.Decode(option.TrafficPattern)
		if err != nil {
			return fmt.Errorf("failed to decode traffic pattern %q: %w", option.TrafficPattern, err)
		}
		if err := mierutp.Validate(trafficPattern); err != nil {
			return fmt.Errorf("invalid traffic pattern %q: %w", option.TrafficPattern, err)
		}
	}
	return nil
}
