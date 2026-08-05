// Package mirage splits a TLS ClientHello across two TLS records so an on-path
// censor cannot match on the server name, while the real server reassembles the
// handshake normally.
//
// The shape is the whole point. Splitting the handshake at a random position
// *inside* the SNI hostname — what most existing implementations do — was
// measured to be dropped by Iran's DPI, even for a hostname that is otherwise
// allowed. What survives is the opposite: one small first record that ends
// *before* the SNI, with the name left intact in the second record, and both
// records written in a single TCP segment. That censor parses only the first
// TLS record looking for a server name; when the name is not there it stops
// looking rather than reassembling the records.
//
// Splitting at the TCP layer instead does not help: the same censor
// reassembles the TCP stream before matching, so this has to happen at the
// record layer.
//
// Enabled by default. Set DM_MIRAGE=0 to turn it off.
package mirage

import (
	"encoding/binary"
	"net"
	"os"
	"strconv"
)

const (
	recordHeaderLen = 5
	handshakeHello  = 0x01
	recordHandshake = 0x16
	extServerName   = 0x0000

	// defaultOffset is how many bytes of the handshake message stay in the
	// small first record: the handshake header plus one byte, always well
	// ahead of the SNI extension.
	defaultOffset = 5
)

var (
	enabled = envBool("DM_MIRAGE", true)
	offset  = envInt("DM_MIRAGE_OFFSET", defaultOffset)
)

// Enabled reports whether Mirage should wrap new TLS connections.
func Enabled() bool { return enabled }

// Wrap returns conn wrapped so that the first ClientHello written to it is
// fragmented. When Mirage is disabled it returns conn untouched.
func Wrap(conn net.Conn) net.Conn {
	if !enabled || conn == nil {
		return conn
	}
	return NewConn(conn, offset)
}

// Conn fragments the first ClientHello written to it; every later write passes
// through untouched.
type Conn struct {
	net.Conn
	offset       int
	firstWritten bool
}

func NewConn(conn net.Conn, offset int) *Conn {
	if offset <= 0 {
		offset = defaultOffset
	}
	return &Conn{Conn: conn, offset: offset}
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.firstWritten {
		return c.Conn.Write(b)
	}
	c.firstWritten = true

	out, ok := split(b, c.offset)
	if !ok {
		// Not something we can fragment - send it exactly as given.
		return c.Conn.Write(b)
	}
	if _, err := c.Conn.Write(out); err != nil {
		return 0, err
	}
	// Report the caller's length: from their point of view the whole buffer
	// was written, which is what io.Writer promises.
	return len(b), nil
}

func (c *Conn) Upstream() any { return c.Conn }

// split rewrites a ClientHello record into two records, the first ending
// before the server name.
func split(record []byte, off int) ([]byte, bool) {
	if off <= 0 {
		off = defaultOffset
	}
	if len(record) <= recordHeaderLen || record[0] != recordHandshake {
		return nil, false
	}
	hs := record[recordHeaderLen:]
	if len(hs) == 0 || hs[0] != handshakeHello {
		return nil, false
	}
	sni := indexSNI(hs)
	if sni < 0 {
		// No server name to hide, so there is nothing to gain.
		return nil, false
	}
	at := off
	if at >= sni {
		at = sni / 2
	}
	if at <= 0 || at >= len(hs) {
		return nil, false
	}

	out := make([]byte, 0, len(record)+recordHeaderLen)
	out = appendRecord(out, record[:3], hs[:at])
	out = appendRecord(out, record[:3], hs[at:])
	return out, true
}

func appendRecord(dst, headerPrefix, payload []byte) []byte {
	dst = append(dst, headerPrefix...)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(payload)))
	return append(dst, payload...)
}

// indexSNI returns the offset of the server name inside a handshake message,
// or -1 when there is none. It refuses to read past the buffer.
func indexSNI(hs []byte) int {
	r := reader{b: hs}
	if !r.skip(4) || !r.skip(2+32) { // handshake header, client_version, random
		return -1
	}
	if !r.skipVector(1) || !r.skipVector(2) || !r.skipVector(1) { // session id, ciphers, compression
		return -1
	}
	if !r.skip(2) { // extensions length
		return -1
	}
	for r.remaining() >= 4 {
		extType, ok := r.uint16()
		if !ok {
			return -1
		}
		extLen, ok := r.uint16()
		if !ok || r.remaining() < int(extLen) {
			return -1
		}
		if extType != extServerName {
			r.skip(int(extLen))
			continue
		}
		if !r.skip(2) || !r.skip(1) { // list length, name type
			return -1
		}
		nameLen, ok := r.uint16()
		if !ok || nameLen == 0 || r.remaining() < int(nameLen) {
			return -1
		}
		return r.pos
	}
	return -1
}

type reader struct {
	b   []byte
	pos int
}

func (r *reader) remaining() int { return len(r.b) - r.pos }

func (r *reader) skip(n int) bool {
	if n < 0 || r.remaining() < n {
		return false
	}
	r.pos += n
	return true
}

func (r *reader) uint16() (uint16, bool) {
	if r.remaining() < 2 {
		return 0, false
	}
	v := binary.BigEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return v, true
}

func (r *reader) skipVector(sizeLen int) bool {
	switch sizeLen {
	case 1:
		if r.remaining() < 1 {
			return false
		}
		n := int(r.b[r.pos])
		r.pos++
		return r.skip(n)
	case 2:
		n, ok := r.uint16()
		if !ok {
			return false
		}
		return r.skip(int(n))
	}
	return false
}

func envBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}
