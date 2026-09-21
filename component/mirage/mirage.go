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
	"net"
	"os"
	"strconv"
	"sync"
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
	offset         int
	firstWritten   bool
	writeMu        sync.Mutex
	writeErr       error
	appliedOffset  int
	appliedRecords int
	recordCount    int
	coalesced      bool
}

func NewConn(conn net.Conn, offset int) *Conn {
	return NewConnWithOptions(conn, offset, records, coalesce)
}

func NewConnWithOptions(conn net.Conn, offset, count int, coalesced bool) *Conn {
	if offset <= 0 {
		offset = defaultOffset
	}
	return &Conn{Conn: conn, offset: offset, recordCount: count, coalesced: coalesced}
}

func (c *Conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if len(b) == 0 {
		return 0, nil
	}
	if c.firstWritten {
		return c.Conn.Write(b)
	}
	c.firstWritten = true

	parts, fragments, ok := mirageParts(b, c.offset, c.recordCount)
	if !ok {
		// Not something we can fragment - send it exactly as given.
		return c.Conn.Write(b)
	}
	n, err := writeMirage(c.Conn, parts, fragments, c.coalesced)
	c.writeErr = err
	if err == nil {
		c.appliedOffset = len(parts[0]) - recordHeaderLen
		c.appliedRecords = fragments
	}
	return n, err
}

// AppliedShape reports what this connection really emitted, not merely the
// requested settings. Unsupported/partial hellos and failed writes report false.
// A future probe driver must check this before crediting a strategy with success.
func (c *Conn) AppliedShape() (offset, records int, coalesce, ok bool) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.appliedOffset, c.appliedRecords, c.coalesced, c.appliedRecords >= 2 && c.writeErr == nil
}

func (c *Conn) Upstream() any { return c.Conn }

// splitN rewrites a ClientHello into n records, the first ending before the
// server name, returned separately so the caller can write each on its own.
//
// Extra records beyond the second are carved out of the remainder AFTER the
// name, never out of the name itself: a cut inside the server name is the one
// shape measured to be dropped even for a hostname that is otherwise allowed.
func splitN(record []byte, off, n int) ([][]byte, bool) {
	parts, _, ok := mirageParts(record, off, n)
	return parts, ok
}

// indexSNI uses the same bounded parser as the production wire codec.
func indexSNI(hs []byte) int {
	start, _, ok := mirageNameRange(hs)
	if !ok {
		return -1
	}
	return start
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
