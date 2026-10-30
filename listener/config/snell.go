package config

import "encoding/json"

type SnellServer struct {
	Listen    string
	Psk       string
	Version   int
	UDP       bool
	ObfsMode  string
	ObfsHost  string
	ShadowTLS ShadowTLS `yaml:"shadow-tls" json:"shadow-tls,omitempty"`
	ResTLS    ResTLS    `yaml:"res-tls" json:"res-tls,omitempty"`
	JLSConfig JLSConfig `yaml:"jls-config" json:"jls-config,omitempty"`

	// Users, when not nil, gives each user (name -> PSK) its own key. The
	// ShadowTLS v3 layer, required then, tells users apart: a user's PSK is
	// also their ShadowTLS password, and Psk and ShadowTLS.Users are unused.
	Users map[string]string `yaml:"-" json:"-"`
}

func (c SnellServer) String() string {
	b, _ := json.Marshal(c)
	return string(b)
}
