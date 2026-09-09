// Package mirage splits a TLS ClientHello across two TLS records so an on-path
// censor cannot match on the server name, while the real server reassembles the
// handshake normally.
//
// The shape is the whole point, and on 2026-09-09 the shape that works
// INVERTED on Hamrah-e Aval. Both records used to go out in a single write.
// That form is now dropped in silence, and the fix is to write each record
// separately.
//
// Measured that evening on a rooted handset on MCI LTE, with a probe using
// this core's own uTLS Chrome fingerprint, against 1.1.1.1:443 with the
// genuinely blocked name instagram.com. A shape that REACHES there has evaded;
// the untouched control is reset, which is what proves the censor is watching.
// Three rounds, order rotated, 15 s between every attempt:
//
//	untouched (control)          0 reached, 3 reset
//	two records, ONE write       0 reached, 3 dropped in silence
//	two records, two writes      3 reached   (at 0, 5, 20 and 50 ms apart)
//	three records, three writes  3 reached
//	two records, split at 64     3 reached
//
// The same pattern held against our own REALITY node on 8443 with its borrowed
// name. And with the old single-write form, this core could not complete ONE
// session on that carrier: a packet capture started before the process caught
// 69 flows to our nodes, all 69 beginning with the 5-byte first record, and not
// one of them received a single byte back.
//
// Two things follow that are worth keeping in mind before anyone "tidies" this:
//
//   - The delay between the writes does nothing. Zero milliseconds passed just
//     as well as fifty. What matters is that the records leave in separate
//     writes, so there is no sleep here to pay for or to fingerprint.
//   - Six shapes passed, not one. If this one is ever detected, the split point
//     and the record count are both free variables.
//
// Splitting at the TCP layer instead still does not help: the censor
// reassembles the TCP stream before matching, so this has to happen at the
// record layer.
//
// ⚠️ Measured on MCI only. An August measurement on Irancell found the exact
// opposite - one write worked and separate writes failed - and whether that is
// a carrier difference or a change over time is NOT established. Do not treat
// either form as universal.
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

	first, second, ok := split(b, c.offset)
	if !ok {
		// Not something we can fragment - send it exactly as given.
		return c.Conn.Write(b)
	}
	// Two writes, deliberately. Concatenating them is the form the censor
	// drops; see the package comment for the measurement.
	if _, err := c.Conn.Write(first); err != nil {
		return 0, err
	}
	if _, err := c.Conn.Write(second); err != nil {
		return 0, err
	}
	// Report the caller's length: from their point of view the whole buffer
	// was written, which is what io.Writer promises.
	return len(b), nil
}

func (c *Conn) Upstream() any { return c.Conn }

// split rewrites a ClientHello record into two records, the first ending
// before the server name, returned separately so the caller can write each in
// its own segment.
func split(record []byte, off int) ([]byte, []byte, bool) {
	if off <= 0 {
		off = defaultOffset
	}
	if len(record) <= recordHeaderLen || record[0] != recordHandshake {
		return nil, nil, false
	}
	hs := record[recordHeaderLen:]
	if len(hs) == 0 || hs[0] != handshakeHello {
		return nil, nil, false
	}
	sni := indexSNI(hs)
	if sni < 0 {
		// No server name to hide, so there is nothing to gain.
		return nil, nil, false
	}
	at := off
	if at >= sni {
		at = sni / 2
	}
	if at <= 0 || at >= len(hs) {
		return nil, nil, false
	}

	first := appendRecord(make([]byte, 0, recordHeaderLen+at), record[:3], hs[:at])
	second := appendRecord(make([]byte, 0, recordHeaderLen+len(hs)-at), record[:3], hs[at:])
	return first, second, true
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
