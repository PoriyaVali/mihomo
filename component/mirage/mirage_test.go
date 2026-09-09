package mirage

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

type captureConn struct {
	net.Conn
	buf    bytes.Buffer
	writes int
}

func (c *captureConn) Write(b []byte) (int, error) {
	c.writes++
	return c.buf.Write(b)
}

// TestShape locks in the shape measured to defeat Iran's SNI-DPI: two records
// in a single segment, the first ending before the server name, the name
// intact in the second.
func TestShape(t *testing.T) {
	hello := clientHello("www.example.com")
	cap := &captureConn{}

	n, err := NewConn(cap, 0).Write(hello)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(hello) {
		t.Fatalf("Write reported %d, want %d", n, len(hello))
	}
	// Each record in its own write. This assertion is the guard, not a detail:
	// the single-write form it used to require is exactly what Hamrah-e Aval
	// began dropping in silence on 2026-09-09, measured 0 reached out of 3
	// against a blocked name while two writes reached 3 of 3. Anyone who
	// "optimises" these back into one buffer breaks the core on that carrier.
	if cap.writes != 2 {
		t.Fatalf("each record must leave in its own write, got %d", cap.writes)
	}

	records := parseRecords(t, cap.buf.Bytes())
	if len(records) != 2 {
		t.Fatalf("want 2 records, got %d", len(records))
	}
	if len(records[0]) != defaultOffset {
		t.Errorf("first record is %d bytes, want %d", len(records[0]), defaultOffset)
	}
	if strings.Contains(string(records[0]), "www.example.com") {
		t.Error("the server name must NOT be in the first record")
	}
	if !strings.Contains(string(records[1]), "www.example.com") {
		t.Error("the server name must stay intact in the second record")
	}
	if got := append(records[0], records[1]...); !bytes.Equal(got, hello[recordHeaderLen:]) {
		t.Error("the two records must reproduce the original handshake exactly")
	}
}

// TestPassThrough makes sure anything that is not a fragmentable ClientHello is
// forwarded byte for byte - a wrong guess here would corrupt real traffic.
func TestPassThrough(t *testing.T) {
	for name, in := range map[string][]byte{
		"not tls": []byte("plain bytes"),
		"short":   {recordHandshake, 0x03, 0x01},
		"no sni":  clientHello("x")[:recordHeaderLen+45],
	} {
		t.Run(name, func(t *testing.T) {
			cap := &captureConn{}
			if _, err := NewConn(cap, 0).Write(in); err != nil {
				t.Fatalf("write: %v", err)
			}
			if !bytes.Equal(cap.buf.Bytes(), in) {
				t.Error("input must be forwarded untouched")
			}
		})
	}
}

func TestOnlyFirstWriteIsSplit(t *testing.T) {
	cap := &captureConn{}
	conn := NewConn(cap, 0)
	if _, err := conn.Write(clientHello("www.example.com")); err != nil {
		t.Fatalf("write: %v", err)
	}
	cap.buf.Reset()
	payload := []byte("application data")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(cap.buf.Bytes(), payload) {
		t.Error("writes after the ClientHello must pass through untouched")
	}
}

// TestIndexSNIRejectsTruncated feeds every truncation of a valid hello to the
// parser; none may panic or point past the buffer.
func TestIndexSNIRejectsTruncated(t *testing.T) {
	hs := clientHello("host.example")[recordHeaderLen:]
	for i := 0; i < len(hs); i++ {
		if at := indexSNI(hs[:i]); at > i {
			t.Fatalf("truncation at %d reported out-of-range index %d", i, at)
		}
	}
}

func TestWrapRespectsDisabled(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	old := enabled
	defer func() { enabled = old }()

	enabled = false
	if _, wrapped := Wrap(c1).(*Conn); wrapped {
		t.Error("Wrap must return the connection untouched when disabled")
	}
	enabled = true
	if _, wrapped := Wrap(c1).(*Conn); !wrapped {
		t.Error("Wrap must fragment when enabled")
	}
}

func parseRecords(t *testing.T, b []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for len(b) > 0 {
		if len(b) < recordHeaderLen {
			t.Fatal("truncated record header")
		}
		n := int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < recordHeaderLen+n {
			t.Fatal("truncated record body")
		}
		out = append(out, b[recordHeaderLen:recordHeaderLen+n])
		b = b[recordHeaderLen+n:]
	}
	return out
}

func clientHello(sni string) []byte {
	name := []byte(sni)
	var ext []byte
	ext = binary.BigEndian.AppendUint16(ext, extServerName)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(name)+5))
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(name)+3))
	ext = append(ext, 0x00)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(name)))
	ext = append(ext, name...)

	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, bytes.Repeat([]byte{0x41}, 32)...)
	body = append(body, 0x00)
	body = binary.BigEndian.AppendUint16(body, 2)
	body = append(body, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	hs := []byte{handshakeHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	rec := []byte{recordHandshake, 0x03, 0x01}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}
