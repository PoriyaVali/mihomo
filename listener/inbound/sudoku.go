package inbound

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sudoku"
	"github.com/metacubex/mihomo/log"
	sudokuproto "github.com/metacubex/mihomo/transport/sudoku"
)

type SudokuOption struct {
	BaseOption
	Key                    string                 `inbound:"key"`
	AEADMethod             string                 `inbound:"aead-method,omitempty"`
	PaddingMin             *int                   `inbound:"padding-min,omitempty"`
	PaddingMax             *int                   `inbound:"padding-max,omitempty"`
	TableType              string                 `inbound:"table-type,omitempty"` // "prefer_ascii", "prefer_entropy", or directional "up_ascii_down_entropy"/"up_entropy_down_ascii"
	HandshakeTimeoutSecond *int                   `inbound:"handshake-timeout,omitempty"`
	EnablePureDownlink     *bool                  `inbound:"enable-pure-downlink,omitempty"`
	CustomTable            string                 `inbound:"custom-table,omitempty"` // optional custom byte layout, e.g. xpxvvpvv
	CustomTables           []string               `inbound:"custom-tables,omitempty"`
	DisableHTTPMask        bool                   `inbound:"disable-http-mask,omitempty"`
	HTTPMaskMode           string                 `inbound:"http-mask-mode,omitempty"` // "legacy" (default), "stream", "poll", "auto"
	PathRoot               string                 `inbound:"path-root,omitempty"`      // optional first-level path prefix for HTTP tunnel endpoints
	Fallback               string                 `inbound:"fallback,omitempty"`
	HTTPMaskOptions        *SudokuHTTPMaskOptions `inbound:"httpmask,omitempty"`
	// Users, when set, accepts only these client keys (name -> key) and
	// attributes each connection to its name. Every key must belong to Key:
	// split private keys of the master key whose public key Key is.
	Users map[string]string `inbound:"users,omitempty"`

	// mihomo private extension (not the part of standard Sudoku protocol)
	MuxOption MuxOption `inbound:"mux-option,omitempty"`
}

type SudokuHTTPMaskOptions struct {
	Disable  bool   `inbound:"disable,omitempty"`
	Mode     string `inbound:"mode,omitempty"`
	PathRoot string `inbound:"path-root,omitempty"`
}

func (o SudokuOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type Sudoku struct {
	*Base
	mu         sync.Mutex
	config     *SudokuOption
	listeners  []*sudoku.Listener
	serverConf LC.SudokuServer
}

func NewSudoku(options *SudokuOption) (*Sudoku, error) {
	if options.Key == "" {
		return nil, fmt.Errorf("sudoku inbound requires key")
	}
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	if err := checkUsers(options.Key, options.Users); err != nil {
		return nil, err
	}

	serverConf := LC.SudokuServer{
		Enable:                 true,
		Listen:                 base.RawAddress(),
		Key:                    options.Key,
		AEADMethod:             options.AEADMethod,
		PaddingMin:             options.PaddingMin,
		PaddingMax:             options.PaddingMax,
		TableType:              options.TableType,
		HandshakeTimeoutSecond: options.HandshakeTimeoutSecond,
		EnablePureDownlink:     options.EnablePureDownlink,
		CustomTable:            options.CustomTable,
		CustomTables:           options.CustomTables,
		DisableHTTPMask:        options.DisableHTTPMask,
		HTTPMaskMode:           options.HTTPMaskMode,
		PathRoot:               strings.TrimSpace(options.PathRoot),
		Fallback:               strings.TrimSpace(options.Fallback),
		Users:                  copyUsers(options.Users),
	}
	if hm := options.HTTPMaskOptions; hm != nil {
		serverConf.DisableHTTPMask = hm.Disable
		if hm.Mode != "" {
			serverConf.HTTPMaskMode = hm.Mode
		}
		if pr := strings.TrimSpace(hm.PathRoot); pr != "" {
			serverConf.PathRoot = pr
		}
	}
	serverConf.MuxOption = options.MuxOption.Build()

	return &Sudoku{
		Base:       base,
		config:     options,
		serverConf: serverConf,
	}, nil
}

// checkUsers rejects a user key that cannot reach this server: a client
// derives the obfuscation tables and AEAD keys from the public key its key
// belongs to, and the server from Key.
func checkUsers(key string, users map[string]string) error {
	seed := sudokuproto.ServerAEADSeed(key)
	for name, userKey := range users {
		if sudokuproto.ClientAEADSeed(userKey) != seed {
			return fmt.Errorf("sudoku user %q: the key does not belong to the server key", name)
		}
	}
	return nil
}

func copyUsers(users map[string]string) map[string]string {
	if users == nil {
		return nil
	}
	out := make(map[string]string, len(users))
	for name, key := range users {
		out[name] = key
	}
	return out
}

// UpdateUsers replaces the accepted client keys without closing the
// listener. Sessions that already completed a handshake keep running: an
// embedder removing a user closes that user's connections itself.
func (s *Sudoku) UpdateUsers(users map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	users = copyUsers(users)
	if users == nil {
		users = map[string]string{}
	}
	if err := checkUsers(s.serverConf.Key, users); err != nil {
		return err
	}
	for _, l := range s.listeners {
		if err := l.SetUsers(users); err != nil {
			return err
		}
	}
	option := *s.config
	option.Users = users
	s.config = &option
	s.serverConf.Users = users
	return nil
}

// Config implements constant.InboundListener
func (s *Sudoku) Config() C.InboundConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.config
}

// Address implements constant.InboundListener
func (s *Sudoku) Address() string {
	var addrList []string
	for _, l := range s.listeners {
		addrList = append(addrList, l.Address())
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (s *Sudoku) Listen(tunnel C.Tunnel) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.serverConf.Key == "" {
		return fmt.Errorf("sudoku inbound requires key")
	}

	var errs []error
	lc := s.ListenConfig()
	for _, addr := range strings.Split(s.RawAddress(), ",") {
		conf := s.serverConf
		conf.Listen = addr

		l, err := sudoku.New(conf, lc, tunnel, s.Additions()...)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		s.listeners = append(s.listeners, l)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	log.Infoln("Sudoku[%s] inbound listening at: %s", s.Name(), s.Address())
	return nil
}

// Close implements constant.InboundListener
func (s *Sudoku) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	for _, l := range s.listeners {
		if err := l.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

var _ C.InboundListener = (*Sudoku)(nil)
