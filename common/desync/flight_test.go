package desync

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type helloCapture struct{ bytes.Buffer }

func (c *helloCapture) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *helloCapture) Close() error                     { return nil }
func (c *helloCapture) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *helloCapture) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *helloCapture) SetDeadline(time.Time) error      { return nil }
func (c *helloCapture) SetReadDeadline(time.Time) error  { return nil }
func (c *helloCapture) SetWriteDeadline(time.Time) error { return nil }
func testHello(t *testing.T, name string) []byte {
	t.Helper()
	c := new(helloCapture)
	client := tls.Client(c, &tls.Config{ServerName: name, InsecureSkipVerify: true})
	_ = client.HandshakeContext(context.Background())
	if c.Len() == 0 {
		t.Fatal("no ClientHello")
	}
	return c.Bytes()
}
func TestFlightMarkersAndRecords(t *testing.T) {
	b := testHello(t, "www.example.com")
	v, complete, err := clientHello(b)
	if err != nil || !complete {
		t.Fatalf("parse: %v, complete %v", err, complete)
	}
	hp, err := tlsPositions(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, spec string
		want       int
	}{{"sni", "sni", hp.start}, {"host offset", "host+1", hp.start + 1}, {"extension", "sniext+1", hp.extension + 1}, {"extensions length", "extlen", hp.extlen}, {"SLD center", "midsld-1", hp.start + 4 + 3 - 1}, {"end", "endhost-1", hp.end - 1}} {
		t.Run(tc.name, func(t *testing.T) {
			cuts, err := positions(b, tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			if cuts[0] != tc.want {
				t.Fatalf("got %v want %d", cuts, tc.want)
			}
		})
	}
	rec, err := recordSplit(b, []int{hp.start + 2, hp.start + 5})
	if err != nil {
		t.Fatal(err)
	}
	rv, ok, err := clientHello(rec)
	if err != nil || !ok {
		t.Fatalf("fragmented parse %v", err)
	}
	if !bytes.Equal(rv.handshake, v.handshake) {
		t.Fatal("record splitting changed handshake")
	}
	cuts, err := positions(rec, "midsld")
	if err != nil {
		t.Fatal(err)
	}
	if cuts[0] != hp.start+4+3+10 {
		t.Fatalf("marker did not account for record headers: %v", cuts)
	}
	fake, err := fakePayload(rec, "a.different.example.net", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	fv, ok, err := clientHello(fake)
	if err != nil || !ok {
		t.Fatalf("fake hello: %v", err)
	}
	fp, err := tlsPositions(fv)
	if err != nil {
		t.Fatal(err)
	}
	if string(fake[fp.start:fp.end]) != "a.different.example.net" {
		t.Fatal("fake SNI not replaced")
	}
	if binary.BigEndian.Uint16(fake[3:]) != uint16(len(fake)-5) {
		t.Fatal("fake record length")
	}
	for i := 1; i < len(b); i++ {
		ok, err := flightComplete(b[:i])
		if err != nil || ok {
			t.Fatalf("partial %d complete=%v err=%v", i, ok, err)
		}
	}
}
func TestFlightHTTPAndValidation(t *testing.T) {
	b := []byte("POST / HTTP/1.1\r\nhOsT: www.example.com\r\nContent-Length: 3\r\n\r\nabc")
	pos, err := positions(b, "host+1,midsld,endhost-1,2,2")
	if err != nil {
		t.Fatal(err)
	}
	if len(pos) != 4 {
		t.Fatal(pos)
	}
	fake, err := fakePayload(b, "", "fake.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fake), "hOsT: fake.example\r\n") || !bytes.HasSuffix(fake, []byte("abc")) {
		t.Fatal(string(fake))
	}
	for _, spec := range []string{"0", "99999", "nope", "host+NaN", ",1"} {
		t.Run(spec, func(t *testing.T) {
			if _, err := positions(b, spec); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	for _, n := range []int{1, 3, 5} {
		t.Run(strings.Repeat("x", n), func(t *testing.T) {
			if _, err := recordSplit(testHello(t, "example.com"), []int{n}); err == nil {
				t.Fatal("record header cut silently ignored")
			}
		})
	}
}
func FuzzClientHello(f *testing.F) {
	f.Add([]byte{22, 3, 1, 0, 2, 1, 0})
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > maxFlight {
			return
		}
		_, _ = flightComplete(b)
		if len(b) > 0 {
			_, _ = positions(b, "sni,midsld")
		}
	})
}
