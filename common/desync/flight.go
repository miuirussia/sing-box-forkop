package desync

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const maxFlight = 256 * 1024

// helloView preserves wire offsets even when a handshake crosses TLS records.
type helloView struct {
	handshake []byte
	wire      []int
	end       int
}

func clientHello(b []byte) (v helloView, complete bool, err error) {
	for p := 0; ; {
		if len(b)-p < 5 {
			return v, false, nil
		}
		if b[p] != 22 || b[p+1] != 3 {
			return v, false, fmt.Errorf("desync: expected TLS handshake record")
		}
		n := int(binary.BigEndian.Uint16(b[p+3 : p+5]))
		if n == 0 || n > 18432 {
			return v, false, fmt.Errorf("desync: invalid TLS record length")
		}
		if len(b)-p-5 < n {
			return v, false, nil
		}
		for j := 0; j < n; j++ {
			v.handshake = append(v.handshake, b[p+5+j])
			v.wire = append(v.wire, p+5+j)
		}
		p += 5 + n
		if len(v.handshake) >= 4 {
			if v.handshake[0] != 1 {
				return v, false, fmt.Errorf("desync: first handshake is not ClientHello")
			}
			size := 4 + int(v.handshake[1])<<16 + int(v.handshake[2])<<8 + int(v.handshake[3])
			if size > maxFlight {
				return v, false, fmt.Errorf("desync: ClientHello exceeds buffer limit")
			}
			if len(v.handshake) >= size {
				v.handshake = v.handshake[:size]
				v.wire = v.wire[:size]
				v.end = p
				return v, true, nil
			}
		}
	}
}

type hostPositions struct{ start, end, extension, extlen, mid int }

func tlsPositions(v helloView) (hostPositions, error) {
	h := v.handshake
	fail := func() (hostPositions, error) {
		return hostPositions{}, fmt.Errorf("desync: malformed ClientHello or missing SNI")
	}
	if len(h) < 39 {
		return fail()
	}
	p := 39 + int(h[38])
	if p+2 > len(h) {
		return fail()
	}
	p += 2 + int(binary.BigEndian.Uint16(h[p:]))
	if p >= len(h) {
		return fail()
	}
	p += 1 + int(h[p])
	if p+2 > len(h) {
		return fail()
	}
	extlen := p
	limit := p + 2 + int(binary.BigEndian.Uint16(h[p:]))
	p += 2
	if limit > len(h) {
		return fail()
	}
	for p+4 <= limit {
		n := int(binary.BigEndian.Uint16(h[p+2:]))
		next := p + 4 + n
		if next > limit {
			return fail()
		}
		if binary.BigEndian.Uint16(h[p:]) == 0 && n >= 5 {
			s := p + 9
			l := int(binary.BigEndian.Uint16(h[p+7:]))
			if s+l > next || l == 0 {
				return fail()
			}
			return hostPositions{v.wire[s], v.wire[s+l-1] + 1, v.wire[p], v.wire[extlen], v.wire[s+middleSLD(string(h[s:s+l]))]}, nil
		}
		p = next
	}
	return fail()
}
func httpPositions(b []byte) (hostPositions, error) {
	offset := 0
	for _, line := range bytes.Split(b, []byte("\r\n")) {
		if colon := bytes.IndexByte(line, ':'); colon >= 0 && strings.EqualFold(string(line[:colon]), "host") {
			s := colon + 1
			for s < len(line) && (line[s] == ' ' || line[s] == '\t') {
				s++
			}
			e := len(line)
			for e > s && (line[e-1] == ' ' || line[e-1] == '\t') {
				e--
			}
			if s < e {
				return hostPositions{offset + s, offset + e, offset, offset + colon, offset + s + middleSLD(string(line[s:e]))}, nil
			}
		}
		offset += len(line) + 2
	}
	return hostPositions{}, fmt.Errorf("desync: HTTP Host missing")
}
func flightComplete(b []byte) (bool, error) {
	if len(b) == 0 {
		return false, nil
	}
	if b[0] == 22 {
		_, ok, err := clientHello(b)
		return ok, err
	}
	// Only hold plausible HTTP method prefixes. Other protocols pass immediately.
	methods := []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "PATCH ", "TRACE "}
	for _, m := range methods {
		if bytes.HasPrefix(b, []byte(m)) || bytes.HasPrefix([]byte(m), b) {
			return bytes.Contains(b, []byte("\r\n\r\n")), nil
		}
	}
	return true, nil
}
func positions(b []byte, spec string) ([]int, error) {
	if spec == "" {
		spec = "1"
	}
	var hp hostPositions
	var parsed bool
	var out []int
	for _, token := range strings.Split(spec, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			return nil, fmt.Errorf("desync: empty split marker")
		}
		n, err := strconv.Atoi(token)
		if err != nil {
			base := token
			delta := 0
			for i := 1; i < len(token); i++ {
				if token[i] == '+' || token[i] == '-' {
					base = token[:i]
					delta, err = strconv.Atoi(token[i:])
					if err != nil {
						return nil, fmt.Errorf("desync: invalid split offset %q", token)
					}
					break
				}
			}
			if !parsed {
				if b[0] == 22 {
					v, ok, e := clientHello(b)
					if e != nil {
						return nil, e
					}
					if !ok {
						return nil, fmt.Errorf("desync: incomplete ClientHello")
					}
					hp, err = tlsPositions(v)
				} else {
					hp, err = httpPositions(b)
				}
				if err != nil {
					return nil, err
				}
				parsed = true
			}
			switch base {
			case "sni", "host":
				n = hp.start
			case "endhost":
				n = hp.end
			case "sniext":
				n = hp.extension
			case "extlen":
				n = hp.extlen
			case "midsld":
				n = hp.mid
			default:
				return nil, fmt.Errorf("desync: unknown split marker %q", base)
			}
			n += delta
		}
		if n <= 0 || n >= len(b) {
			return nil, fmt.Errorf("desync: split %q outside first flight (%d bytes)", token, len(b))
		}
		out = append(out, n)
	}
	sort.Ints(out)
	return compactPositions(out), nil
}
func compactPositions(in []int) []int {
	out := in[:0]
	for _, n := range in {
		if len(out) == 0 || out[len(out)-1] != n {
			out = append(out, n)
		}
	}
	return out
}

// recordSplit adds only TLS record headers; handshake bytes are unchanged.
func recordSplit(b []byte, cuts []int) ([]byte, error) {
	var out []byte
	used := make(map[int]bool)
	for p := 0; p < len(b); {
		if len(b)-p < 5 || b[p] != 22 {
			out = append(out, b[p:]...)
			break
		}
		end := p + 5 + int(binary.BigEndian.Uint16(b[p+3:]))
		if end > len(b) {
			return nil, fmt.Errorf("desync: truncated TLS record")
		}
		start := p + 5
		for _, cut := range append(append([]int(nil), cuts...), end) {
			if cut <= start || cut > end {
				continue
			}
			used[cut] = true
			h := append([]byte(nil), b[p:p+5]...)
			binary.BigEndian.PutUint16(h[3:], uint16(cut-start))
			out = append(out, h...)
			out = append(out, b[start:cut]...)
			start = cut
		}
		p = end
	}
	for _, cut := range cuts {
		if !used[cut] {
			return nil, fmt.Errorf("desync: TLS record split %d is in a record header or boundary", cut)
		}
	}
	return out, nil
}
func fakePayload(real []byte, sni, host string, custom []byte) ([]byte, error) {
	if len(custom) > 0 {
		return append([]byte(nil), custom...), nil
	}
	if real[0] == 22 {
		v, ok, err := clientHello(real)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("desync: incomplete fake source")
		}
		h := append([]byte(nil), v.handshake...)
		hp, err := tlsPositions(helloView{handshake: h, wire: identity(len(h))})
		if err != nil {
			return nil, err
		}
		if sni == "" {
			sni = "www.example.com"
		}
		delta := len(sni) - (hp.end - hp.start)
		h = append(append(append([]byte(nil), h[:hp.start]...), []byte(sni)...), h[hp.end:]...)
		binary.BigEndian.PutUint16(h[hp.extension+2:], uint16(int(binary.BigEndian.Uint16(h[hp.extension+2:]))+delta))
		binary.BigEndian.PutUint16(h[hp.extension+4:], uint16(len(sni)+3))
		binary.BigEndian.PutUint16(h[hp.extension+7:], uint16(len(sni)))
		binary.BigEndian.PutUint16(h[hp.extlen:], uint16(int(binary.BigEndian.Uint16(h[hp.extlen:]))+delta))
		n := len(h) - 4
		h[1] = byte(n >> 16)
		h[2] = byte(n >> 8)
		h[3] = byte(n)
		var out []byte
		for len(h) > 0 {
			n := min(len(h), 16384)
			out = append(out, 22, 3, 1, byte(n>>8), byte(n))
			out = append(out, h[:n]...)
			h = h[n:]
		}
		return out, nil
	}
	hp, err := httpPositions(real)
	if err != nil {
		return nil, err
	}
	if host == "" {
		host = "www.example.com"
	}
	return append(append(append([]byte(nil), real[:hp.start]...), host...), real[hp.end:]...), nil
}
func identity(n int) []int {
	v := make([]int, n)
	for i := range v {
		v[i] = i
	}
	return v
}

func middleSLD(host string) int {
	labels := strings.Split(host, ".")
	idx := len(labels) - 2
	if idx < 0 {
		idx = 0
	}
	prefix := 0
	for j := 0; j < idx; j++ {
		prefix += len(labels[j]) + 1
	}
	return prefix + len(labels[idx])/2
}
