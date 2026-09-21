package mirage

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// The shape has to be steerable, because the two carriers measured on
// 2026-09-09 disagreed about it and neither answer is guaranteed to last.
//
// splitN is what the panel's record count reaches. These exercise it directly,
// since the package-level knobs are read once at init and cannot be varied
// inside one test binary.
type shapeConn struct {
	net.Conn
	buf    bytes.Buffer
	writes int
}

func (c *shapeConn) Write(b []byte) (int, error) {
	c.writes++
	return c.buf.Write(b)
}

func recordSizes(t *testing.T, b []byte) []int {
	t.Helper()
	var out []int
	for len(b) > 0 {
		if len(b) < recordHeaderLen {
			t.Fatalf("truncated record header, %d bytes left", len(b))
		}
		n := int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < recordHeaderLen+n {
			t.Fatalf("record claims %d bytes, %d present", n, len(b)-recordHeaderLen)
		}
		out = append(out, n)
		b = b[recordHeaderLen+n:]
	}
	return out
}

func TestSplitNProducesTheRequestedRecordCount(t *testing.T) {
	// Additional safe cuts require post-SNI bytes.
	hello := paddedMirageHello("www.example.com", 64)
	for _, n := range []int{2, 3, 4} {
		parts, ok := splitN(hello, defaultOffset, n)
		if !ok {
			t.Fatalf("n=%d: refused a valid ClientHello", n)
		}
		if len(parts) != n {
			t.Fatalf("n=%d: got %d records", n, len(parts))
		}
		// The pieces must still reassemble into the original handshake, or the
		// server cannot parse what the censor let through.
		var body []byte
		for _, p := range parts {
			body = append(body, p[recordHeaderLen:]...)
		}
		if !bytes.Equal(body, hello[recordHeaderLen:]) {
			t.Fatalf("n=%d: records do not reassemble to the original handshake", n)
		}
		// And the name must never be cut, at any record count. A cut inside
		// the server name is the one shape measured to be dropped even for a
		// hostname that is otherwise allowed.
		if bytes.Contains(parts[0], []byte("www.example.com")) {
			t.Fatalf("n=%d: the name is in the first record", n)
		}
		var whole bool
		for _, p := range parts[1:] {
			whole = whole || bytes.Contains(p, []byte("www.example.com"))
		}
		if !whole {
			t.Fatalf("n=%d: the name was split across records", n)
		}
	}
}

// Asking for more records than there is material for must degrade, not fail:
// a refusal here would send the hello untouched, which is the shape that gets
// reset on a blocked name.
func TestSplitNDegradesRatherThanRefusing(t *testing.T) {
	hello := clientHello("a.io")
	parts, ok := splitN(hello, defaultOffset, 64)
	if !ok {
		t.Fatal("refused rather than degrading")
	}
	if len(parts) < 2 {
		t.Fatalf("degraded past the point of fragmenting at all: %d records", len(parts))
	}
	sizes := recordSizes(t, bytes.Join(parts, nil))
	for i, n := range sizes {
		if n == 0 {
			t.Fatalf("record %d is empty; an empty TLS record is not something a client sends", i)
		}
	}
}

// Whatever the record count, one write per record is the default and the
// coalesced form is the exception - that is the distinction MCI acts on.
func TestConnWritesOneRecordPerWrite(t *testing.T) {
	hello := clientHello("www.example.com")
	cap := &shapeConn{}
	if _, err := NewConn(cap, 0).Write(hello); err != nil {
		t.Fatal(err)
	}
	if cap.writes != records {
		t.Fatalf("%d writes for %d records", cap.writes, records)
	}
	if got := len(recordSizes(t, cap.buf.Bytes())); got != records {
		t.Fatalf("%d records on the wire, want %d", got, records)
	}
}
