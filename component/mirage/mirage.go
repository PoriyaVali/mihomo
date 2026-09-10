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
// Irancell was measured the same evening with the data SIM switched on the same
// handset, same probe, three rounds, order rotated, 20 s apart: EVERY
// fragmented shape passed there, including the single-write form MCI kills, and
// the August note claiming separate writes always failed on Irancell did not
// reproduce - twelve of twelve reached.
//
// 🔑 So two records in two writes is the only shape measured to pass on BOTH
// carriers, which is why it is the default.
//
// ⚠️ But the carriers behave differently enough that the shape must stay
// steerable. Against a genuinely blocked name, no shape reached on Irancell at
// all - zero of 24 - while two writes reached on MCI. MCI matches on the SHAPE
// and can be evaded by changing it; Irancell matches on the NAME, which
// fragmentation does not hide. A borrowed name that gets blocked cannot be
// rescued by anything here.
//
// Every knob below is settable from the panel so the next disagreement costs a
// setting rather than a release:
//
//	DM_MIRAGE=0            off entirely
//	DM_MIRAGE_OFFSET=n     where the first record ends (5 and 64 both measured)
//	DM_MIRAGE_RECORDS=n    how many records (2 and 3 both measured)
//	DM_MIRAGE_COALESCE=1   the old single-write form, for a network that wants it
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

	// coalesce puts every record in one write instead of one write each.
	//
	// This exists because the two carriers measured on 2026-09-09 disagreed:
	// MCI drops the single-write form and Irancell accepts either, so two
	// writes is what ships. But the disagreement is the point - a censor that
	// starts matching on separate writes would leave us with no answer that
	// does not need a new build, and the shape is not something an offset can
	// express. DM_MIRAGE_COALESCE=1 restores the old form from the panel.
	coalesce = envBool("DM_MIRAGE_COALESCE", false)

	// records is how many TLS records the handshake is cut into. Three was
	// measured to pass on both carriers as well, so it is a real alternative
	// rather than a guess, and it is the other free variable if the two-record
	// shape is ever singled out.
	records = envInt("DM_MIRAGE_RECORDS", 2)
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

	parts, ok := splitN(b, c.offset, records)
	if !ok {
		// Not something we can fragment - send it exactly as given.
		return c.Conn.Write(b)
	}
	// One write per record by default. Concatenating them is the form MCI
	// drops; see the package comment for the measurement. The panel can ask
	// for the old shape back without a build.
	if coalesce {
		var all []byte
		for _, r := range parts {
			all = append(all, r...)
		}
		if _, err := c.Conn.Write(all); err != nil {
			return 0, err
		}
		return len(b), nil
	}
	for _, r := range parts {
		if _, err := c.Conn.Write(r); err != nil {
			return 0, err
		}
	}
	// Report the caller's length: from their point of view the whole buffer
	// was written, which is what io.Writer promises.
	return len(b), nil
}

func (c *Conn) Upstream() any { return c.Conn }

// splitN rewrites a ClientHello into n records, the first ending before the
// server name, returned separately so the caller can write each on its own.
//
// Extra records beyond the second are carved out of the remainder AFTER the
// name, never out of the name itself: a cut inside the server name is the one
// shape measured to be dropped even for a hostname that is otherwise allowed.
func splitN(record []byte, off, n int) ([][]byte, bool) {
	first, second, ok := split(record, off)
	if !ok {
		return nil, false
	}
	parts := [][]byte{first, second}
	// Re-cut the tail, which is a complete record, into n-1 pieces.
	for len(parts) < n {
		tail := parts[len(parts)-1]
		body := tail[recordHeaderLen:]
		if len(body) < 2 {
			break // nothing left worth cutting
		}
		at := len(body) / 2
		parts = parts[:len(parts)-1]
		parts = append(parts,
			appendRecord(make([]byte, 0, recordHeaderLen+at), tail[:3], body[:at]),
			appendRecord(make([]byte, 0, recordHeaderLen+len(body)-at), tail[:3], body[at:]))
	}
	return parts, true
}

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
