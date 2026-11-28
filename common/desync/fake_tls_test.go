package desync

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestTransformFakeTLSDisabled(t *testing.T) {
	t.Parallel()
	for _, template := range []string{"", "original"} {
		t.Run(template, func(t *testing.T) {
			for _, input := range [][]byte{nil, []byte("custom binary fake"), fakeTLSFixture()} {
				before := bytes.Clone(input)
				got, err := transformFakeTLS(input, false, 0, template)
				if err != nil || !bytes.Equal(got, before) || !bytes.Equal(input, before) {
					t.Fatalf("disabled transformation changed bytes: %v", err)
				}
			}
		})
	}
}

func TestTransformFakeTLSRandomization(t *testing.T) {
	t.Parallel()
	input := fakeTLSFixture()
	before := bytes.Clone(input)
	first, err := transformFakeTLS(input, true, 0, "original")
	if err != nil {
		t.Fatal(err)
	}
	second, err := transformFakeTLS(input, true, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, before) || bytes.Equal(first, second) {
		t.Fatal("source changed or separate randomizations reused the same entropy")
	}
	fakeTLSInspect(t, first)
	fakeTLSInspect(t, second)
	// All changing fields have deliberately distinct fixture bytes. Mask them
	// and require everything else (including framing and SNI) to stay identical.
	for _, field := range [][]byte{bytes.Repeat([]byte{0xa1}, 32), bytes.Repeat([]byte{0xb2}, 32), bytes.Repeat([]byte{0xc3}, 32), append([]byte{4}, bytes.Repeat([]byte{0xd4}, 64)...)} {
		start := bytes.Index(before, field)
		if start < 0 {
			t.Fatal("test field missing")
		}
		if bytes.Equal(first[start:start+len(field)], field) || bytes.Equal(second[start:start+len(field)], field) {
			t.Fatal("fake random/session/key material was not randomized")
		}
		copy(first[start:start+len(field)], field)
		copy(second[start:start+len(field)], field)
	}
	if !bytes.Equal(first, before) || !bytes.Equal(second, before) {
		t.Fatal("randomization changed bytes outside Random, SessionID and key-exchange data")
	}
}

func TestTransformFakeTLSCompact(t *testing.T) {
	t.Parallel()
	input := fakeTLSFixture(
		fakeTLSTestExtension(21, make([]byte, 80)),
		fakeTLSTestExtension(42, nil),
		fakeTLSTestExtension(41, fakeTLSTestPSK()),
	)
	before := bytes.Clone(input)
	got, err := transformFakeTLS(input, false, 0, "compact")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) >= len(input) || !bytes.Equal(input, before) {
		t.Fatal("compact failed to shrink the fake or changed its input")
	}
	info := fakeTLSInspect(t, got)
	if info.ServerName != "www.example.com" || !slices.Contains(info.SupportedVersions, tls.VersionTLS13) || len(info.SupportedCurves) != 2 || len(info.SignatureSchemes) != 2 {
		t.Fatalf("compact lost required negotiation data: %+v", info)
	}
	if len(info.SupportedProtos) != 0 {
		t.Fatal("compact retained optional ALPN")
	}
	if bytes.Contains(got, []byte("fixture-psk-identity")) || bytes.Contains(got, bytes.Repeat([]byte{0xee}, 32)) {
		t.Fatal("compact retained PSK identities or binders")
	}
	if bytes.Contains(got, fakeTLSTestExtension(42, nil)) {
		t.Fatal("compact retained early_data")
	}
}

func TestTransformFakeTLSExactWireSize(t *testing.T) {
	t.Parallel()
	input := fakeTLSFixture()
	for _, size := range []int{len(input), len(input) + 4, 512, 16388, 16389, 16390, 16394, 16395, 32778, 32779, 32780, 60000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			got, err := transformFakeTLS(input, false, size, "original")
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != size {
				t.Fatalf("wire size %d, want %d", len(got), size)
			}
			fakeTLSInspect(t, got)
			for p := 0; p < len(got); {
				if len(got)-p < 5 || got[p] != 22 {
					t.Fatal("non-handshake data emitted")
				}
				n := int(binary.BigEndian.Uint16(got[p+3:]))
				if n == 0 || n > 16384 || n > len(got)-p-5 {
					t.Fatalf("invalid record size %d", n)
				}
				p += 5 + n
			}
		})
	}
	for _, size := range []int{-1, 1, len(input) - 1, len(input) + 1, len(input) + 2, len(input) + 3, 60001} {
		t.Run("impossible_"+fmt.Sprint(size), func(t *testing.T) {
			if got, err := transformFakeTLS(input, false, size, ""); err == nil || got != nil {
				t.Fatal("impossible target did not fail before producing output")
			}
		})
	}
}

func TestTransformFakeTLSResizesExistingPaddingAndPSK(t *testing.T) {
	t.Parallel()
	input := fakeTLSFixture(fakeTLSTestExtension(21, make([]byte, 800)), fakeTLSTestExtension(41, fakeTLSTestPSK()))
	for _, size := range []int{512, 2048, 16390} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			got, err := transformFakeTLS(input, false, size, "")
			if err != nil || len(got) != size {
				t.Fatalf("resize: size=%d err=%v", len(got), err)
			}
			fakeTLSInspect(t, got) // The independent TLS parser enforces PSK last.
			v, _, _ := clientHello(got)
			if !bytes.HasSuffix(v.handshake, fakeTLSTestExtension(41, fakeTLSTestPSK())) {
				t.Fatal("padding moved PSK or changed its binder")
			}
		})
	}
}

func TestTransformFakeTLSOnlyClientHello(t *testing.T) {
	t.Parallel()
	input := fakeTLSFixture()
	// Exercise handshake headers split between records, not just extension data.
	fragmented, err := recordSplit(input, []int{6, 8, 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, sameRecord := range []bool{false, true} {
		t.Run(fmt.Sprint(sameRecord), func(t *testing.T) {
			withTail := bytes.Clone(fragmented)
			tail := []byte("Host: real.example\r\nPRIVATE APPLICATION DATA")
			if sameRecord {
				withTail = bytes.Clone(input)
				binary.BigEndian.PutUint16(withTail[3:], uint16(len(input)-5+len(tail)))
			} else {
				withTail = append(withTail, 23, 3, 3, 0, byte(len(tail)))
			}
			withTail = append(withTail, tail...)
			before := bytes.Clone(withTail)
			got, err := transformFakeTLS(withTail, false, 0, "compact")
			if err != nil {
				t.Fatal(err)
			}
			fakeTLSInspect(t, got)
			if bytes.Contains(got, tail) || !bytes.Equal(withTail, before) {
				t.Fatal("fake leaked trailing real bytes or modified input")
			}
		})
	}
}

func TestTransformFakeTLSRealClientAndLegacyHello(t *testing.T) {
	t.Parallel()
	capture := &fakeTLSMemoryConn{}
	_ = tls.Client(capture, &tls.Config{ServerName: "real.example", InsecureSkipVerify: true}).HandshakeContext(context.Background())
	got, err := transformFakeTLS(capture.output.Bytes(), true, 60000, "compact")
	if err != nil {
		t.Fatal(err)
	}
	if info := fakeTLSInspect(t, got); info.ServerName != "real.example" {
		t.Fatal("real ClientHello SNI lost")
	}
	// A TLS 1.2 ClientHello with empty SessionID and no extensions is legal.
	legacy := []byte{22, 3, 1, 0, 45, 1, 0, 0, 41, 3, 3}
	legacy = append(legacy, make([]byte, 32)...)
	legacy = append(legacy, 0, 0, 2, 0xc0, 0x2f, 1, 0)
	for _, size := range []int{0, len(legacy), 256} {
		got, err := transformFakeTLS(legacy, true, size, "")
		if err != nil || (size != 0 && len(got) != size) {
			t.Fatalf("legacy size %d: %v", size, err)
		}
		fakeTLSInspect(t, got)
	}
}

func TestTransformFakeTLSRejectsMalformedInput(t *testing.T) {
	t.Parallel()
	input := fakeTLSFixture()
	cases := []struct {
		name string
		data []byte
	}{
		{"custom non-TLS", []byte("custom fake")},
		{"truncated record", input[:len(input)-1]},
		{"duplicate extension", fakeTLSFixture(fakeTLSTestExtension(43, []byte{2, 3, 4}))},
		{"bad key share", fakeTLSFixtureWithKeyShare([]byte{0, 4, 0, 29, 0, 33})},
		{"bad padding", fakeTLSFixture(fakeTLSTestExtension(21, []byte{1}))},
		{"bad binder", fakeTLSFixture(fakeTLSTestExtension(41, []byte{0, 0, 0, 0}))},
		{"PSK not last", fakeTLSFixture(fakeTLSTestExtension(41, fakeTLSTestPSK()), fakeTLSTestExtension(21, nil))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := bytes.Clone(tc.data)
			got, err := transformFakeTLS(tc.data, true, 0, "compact")
			if err == nil || got != nil || !strings.Contains(err.Error(), "TLS") || !bytes.Equal(tc.data, before) {
				t.Fatalf("malformed input not safely rejected: %v", err)
			}
		})
	}
	if _, err := transformFakeTLS(input, false, 0, "unknown"); err == nil {
		t.Fatal("unknown template accepted")
	}
	// Every truncated prefix, including prefixes within vector lengths, must
	// fail explicitly rather than panic or emit a partially parsed fake.
	for n := 0; n < len(input); n++ {
		if _, err := transformFakeTLS(input[:n], true, 0, ""); err == nil {
			t.Fatalf("truncated prefix %d accepted", n)
		}
	}
}

func FuzzTransformFakeTLS(f *testing.F) {
	f.Add(fakeTLSFixture(), 512, true)
	f.Add([]byte("not TLS"), 0, false)
	f.Fuzz(func(t *testing.T, input []byte, size int, randomize bool) {
		if len(input) > maxFlight {
			return
		}
		before := bytes.Clone(input)
		got, err := transformFakeTLS(input, randomize, size, "compact")
		if !bytes.Equal(input, before) {
			t.Fatal("input mutated")
		}
		if err == nil {
			if size != 0 && len(got) != size {
				t.Fatal("inexact size")
			}
			v, complete, err := clientHello(got)
			if err != nil || !complete || v.end != len(got) {
				t.Fatalf("output is not a complete isolated ClientHello: %v", err)
			}
		}
	})
}

func fakeTLSFixture(extra ...[]byte) []byte {
	key := []byte{0, 29, 0, 32}
	key = append(key, bytes.Repeat([]byte{0xc3}, 32)...)
	key = append(key, 0, 23, 0, 65, 4)
	key = append(key, bytes.Repeat([]byte{0xd4}, 64)...)
	return fakeTLSFixtureBuild(append(binary.BigEndian.AppendUint16(nil, uint16(len(key))), key...), extra...)
}

func fakeTLSFixtureWithKeyShare(key []byte) []byte {
	return fakeTLSFixtureBuild(key)
}

func fakeTLSFixtureBuild(key []byte, extra ...[]byte) []byte {
	sni := []byte("www.example.com")
	name := append([]byte{0, 0, byte(len(sni))}, sni...)
	ext := fakeTLSTestExtension(0, append(binary.BigEndian.AppendUint16(nil, uint16(len(name))), name...))
	for _, e := range [][]byte{
		fakeTLSTestExtension(10, []byte{0, 4, 0, 29, 0, 23}),
		fakeTLSTestExtension(13, []byte{0, 4, 8, 4, 4, 3}),
		fakeTLSTestExtension(43, []byte{4, 3, 4, 3, 3}),
		fakeTLSTestExtension(45, []byte{1, 1}),
		fakeTLSTestExtension(51, key),
		fakeTLSTestExtension(16, []byte{0, 3, 2, 'h', '2'}),
	} {
		ext = append(ext, e...)
	}
	for _, e := range extra {
		ext = append(ext, e...)
	}
	body := append([]byte{3, 3}, bytes.Repeat([]byte{0xa1}, 32)...)
	body = append(body, 32)
	body = append(body, bytes.Repeat([]byte{0xb2}, 32)...)
	body = append(body, 0, 6, 0x13, 1, 0x13, 2, 0xc0, 0x2f, 1, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	handshake := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	wire := []byte{22, 3, 1, byte(len(handshake) >> 8), byte(len(handshake))}
	return append(wire, handshake...)
}

func fakeTLSTestExtension(typ uint16, data []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, typ)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

func fakeTLSTestPSK() []byte {
	identity := []byte("fixture-psk-identity")
	identities := binary.BigEndian.AppendUint16(nil, uint16(len(identity)))
	identities = append(identities, identity...)
	identities = append(identities, 0, 0, 0, 0)
	b := binary.BigEndian.AppendUint16(nil, uint16(len(identities)))
	b = append(b, identities...)
	b = append(b, 0, 33, 32)
	return append(b, bytes.Repeat([]byte{0xee}, 32)...)
}

// Use crypto/tls, rather than the production parser, to verify that transformed
// messages remain parseable. Stop after parsing, before fake keys authenticate.
func fakeTLSInspect(t *testing.T, wire []byte) *tls.ClientHelloInfo {
	t.Helper()
	var info *tls.ClientHelloInfo
	stop := errors.New("test: ClientHello parsed")
	conn := &fakeTLSMemoryConn{input: bytes.NewReader(wire)}
	err := tls.Server(conn, &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		info = hello
		return nil, stop
	}}).HandshakeContext(context.Background())
	if !errors.Is(err, stop) || info == nil {
		t.Fatalf("crypto/tls rejected transformed ClientHello: %v", err)
	}
	return info
}

type fakeTLSMemoryConn struct {
	input  *bytes.Reader
	output bytes.Buffer
}

func (c *fakeTLSMemoryConn) Read(b []byte) (int, error) {
	if c.input == nil {
		return 0, io.EOF
	}
	return c.input.Read(b)
}

func (c *fakeTLSMemoryConn) Write(b []byte) (int, error) { return c.output.Write(b) }
func (c *fakeTLSMemoryConn) Close() error                { return nil }
func (c *fakeTLSMemoryConn) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (c *fakeTLSMemoryConn) RemoteAddr() net.Addr        { return &net.TCPAddr{} }
func (c *fakeTLSMemoryConn) SetDeadline(time.Time) error { return nil }
func (c *fakeTLSMemoryConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *fakeTLSMemoryConn) SetWriteDeadline(time.Time) error { return nil }
