package mieru

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	mierucommon "github.com/enfein/mieru/v3/apis/common"
	mierumodel "github.com/enfein/mieru/v3/apis/model"
	mieruserver "github.com/enfein/mieru/v3/apis/server"
	mierutp "github.com/enfein/mieru/v3/apis/trafficpattern"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlcommon"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	mierudefault "github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/protocol"
	"google.golang.org/protobuf/proto"
)

// Server is the server of github.com/enfein/mieru/v3/apis/server (GPL-3.0,
// v3.38.0) with SetUsers added, which replaces the users of a running server.
// Sessions that already authenticated keep their credential; an embedder that
// removes a user closes that user's sessions itself.
type Server struct {
	mu      sync.Mutex
	running atomic.Bool
	config  *mieruserver.ServerConfig
	mux     *protocol.Mux
}

// NewServer validates config as the mieru API's Store does.
func NewServer(config *mieruserver.ServerConfig) (*Server, error) {
	if err := mieruserver.NewServer().Store(config); err != nil {
		return nil, err
	}
	return &Server{config: config}, nil
}

func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mux = protocol.NewMux(false)
	if s.config.StreamListenerFactory != nil {
		s.mux.SetStreamListenerFactory(s.config.StreamListenerFactory)
	}
	if s.config.PacketListenerFactory != nil {
		s.mux.SetPacketListenerFactory(s.config.PacketListenerFactory)
	}
	trafficPattern, err := mierutp.NewConfig(s.config.Config.TrafficPattern)
	if err != nil {
		return err
	}
	s.mux.SetTrafficPattern(trafficPattern).
		SetServerUsers(appctlcommon.UserListToMap(s.config.Config.GetUsers())).
		SetServerUserHintIsMandatory(s.config.Config.GetAdvancedSettings().GetUserHintIsMandatory())
	mtu := mierudefault.DefaultMTU
	if s.config.Config.GetMtu() != 0 {
		mtu = int(s.config.Config.GetMtu())
	}
	endpoints, err := appctlcommon.AddrPortToUnderlayProperties(s.config.Config.GetListenIPAddress(), s.config.Config.GetPortBindings(), mtu)
	if err != nil {
		return err
	}
	s.mux.SetEndpoints(endpoints)
	if err := s.mux.Start(); err != nil {
		return err
	}
	s.running.Store(true)
	return nil
}

// SetUsers validates users as a new configuration and publishes them to the
// running mux atomically. New sessions authenticate against them at once.
func (s *Server) SetUsers(users []*mierupb.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	config := proto.Clone(s.config.Config).(*mierupb.ServerConfig)
	config.Users = users
	next := &mieruserver.ServerConfig{Config: config, StreamListenerFactory: s.config.StreamListenerFactory, PacketListenerFactory: s.config.PacketListenerFactory}
	if err := mieruserver.NewServer().Store(next); err != nil {
		return err
	}
	s.config = next
	if s.mux != nil {
		s.mux.SetServerUsers(appctlcommon.UserListToMap(users))
	}
	return nil
}

func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running.Store(false)
	if s.mux != nil {
		s.mux.Close()
	}
	return nil
}

func (s *Server) IsRunning() bool {
	return s.running.Load()
}

func (s *Server) Accept() (net.Conn, *mierumodel.Request, error) {
	conn, err := s.mux.Accept()
	if err != nil {
		return nil, nil, err
	}
	if _, ok := conn.(mierucommon.UserContext); !ok {
		return nil, nil, fmt.Errorf("internal error: connection doesn't implement UserContext interface")
	}
	mierudefault.SetReadTimeout(conn, 10*time.Second)
	defer func() {
		mierudefault.SetReadTimeout(conn, 0)
	}()
	req := &mierumodel.Request{}
	if err := req.ReadFromSocks5(conn); err != nil {
		return nil, nil, err
	}
	return conn, req, nil
}
