package outbound

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	C "github.com/metacubex/mihomo/constant"
)

// MirageAnyTLS accepts only the parser's lifetime wrapper, not arbitrary
// protocol wrappers (for example smux) whose wire behavior is not attested.
func MirageAnyTLS(adapter C.ProxyAdapter) *AnyTLS {
	if wrapped, ok := adapter.(*autoCloseProxyAdapter); ok {
		adapter = wrapped.ProxyAdapter
	}
	node, _ := adapter.(*AnyTLS)
	return node
}

// MirageRevision fingerprints the entire concrete outbound, not a display name
// or a caller-supplied endpoint. No credentials are returned to the controller.
func (t *AnyTLS) MirageRevision() string {
	o := *t.option
	// Nested dialer chains and custom TLS framing are not attested by this probe.
	if o.DialerProxy != "" || o.DialerForAPI != nil {
		return ""
	}
	// The normal config parser supplies TunnelForAPI to EVERY node. BasicOption
	// only consults it when DialerProxy is nonempty (rejected above); it does not
	// change a direct AnyTLS dial. Do not serialize this runtime service object.
	o.TunnelForAPI = nil
	shadow, e1 := o.ShadowTLSOpts.Parse()
	restls, e2 := o.RestlsOpts.Parse(o.SNI, o.ClientFingerprint)
	jls, e3 := o.JLSOpts.Parse()
	if e1 != nil || e2 != nil || e3 != nil || shadow != nil || restls != nil || jls != nil {
		return ""
	}
	data, err := json.Marshal(o)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return "anytls-" + hex.EncodeToString(sum[:])
}

// CloneForMirage creates a cold independent authenticated AnyTLS session with
// the real core's options, fingerprint, credentials, resolver and protected dialer.
func (t *AnyTLS) CloneForMirage() (*AnyTLS, error) {
	if t.MirageRevision() == "" {
		return nil, errors.New("unsupported Mirage outbound")
	}
	option := *t.option
	option.DisableReuse = true
	option.MinIdleSession = 0
	return NewAnyTLS(option)
}
