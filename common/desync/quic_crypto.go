package desync

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

type initialFrame struct {
	typ    uint64
	raw    []byte
	offset uint64
	data   []byte
}

// Only frame types permitted in Initial have known boundaries here. An unknown
// type makes the entire payload opaque: guessing its length could corrupt data.
func initialFrames(plain []byte) ([]initialFrame, bool, error) {
	var frames []initialFrame
	p := 0
	read := func() (uint64, error) {
		v, n, err := readQUICVarint(plain, p)
		p += n
		return v, err
	}
	skip := func(n uint64) error {
		if n > uint64(len(plain)-p) {
			return io.ErrUnexpectedEOF
		}
		p += int(n)
		return nil
	}
	for p < len(plain) {
		start := p
		typ, err := read()
		if err != nil {
			return nil, false, fmt.Errorf("desync: malformed Initial frame: %w", err)
		}
		f := initialFrame{typ: typ}
		switch typ {
		case 0, 1: // PADDING, PING
			if typ == 0 {
				for p < len(plain) && plain[p] == 0 {
					p++
				}
			}
		case 2, 3: // ACK, ACK_ECN
			var largest, ranges, first uint64
			largest, err = read()
			if err == nil {
				_, err = read() // delay
			}
			if err == nil {
				ranges, err = read()
			}
			if err == nil {
				first, err = read()
			}
			if err == nil && (first > largest || ranges > uint64((len(plain)-p)/2)) {
				err = fmt.Errorf("invalid ACK ranges")
			}
			low := largest - first
			for i := uint64(0); i < ranges && err == nil; i++ {
				var gap, size uint64
				gap, err = read()
				if err == nil {
					size, err = read()
				}
				if err == nil {
					if low < 2 || gap > low-2 || size > low-gap-2 {
						err = fmt.Errorf("invalid ACK range")
					} else {
						low -= gap + 2 + size
					}
				}
			}
			if typ == 3 {
				for i := 0; i < 3 && err == nil; i++ {
					_, err = read()
				}
			}
		case 6: // CRYPTO
			f.offset, err = read()
			var size uint64
			if err == nil {
				size, err = read()
			}
			if err == nil && size > (uint64(1)<<62)-1-f.offset {
				err = fmt.Errorf("CRYPTO offset overflow")
			}
			if err == nil {
				at := p
				err = skip(size)
				if err == nil {
					f.data = plain[at:p]
				}
			}
		case 0x1c: // transport CONNECTION_CLOSE
			_, err = read()
			if err == nil {
				_, err = read()
			}
			var size uint64
			if err == nil {
				size, err = read()
			}
			if err == nil {
				err = skip(size)
			}
		default:
			return nil, false, nil
		}
		if err != nil {
			return nil, false, fmt.Errorf("desync: malformed Initial frame %#x: %w", typ, err)
		}
		f.raw = plain[start:p]
		frames = append(frames, f)
	}
	return frames, true, nil
}

// Reassembly is local to this packet and bounded by the synthetic TLS flight.
// Gaps and incomplete ClientHellos leave semantic positions unresolved.
func initialCryptoHello(frames []initialFrame) []byte {
	var crypto []initialFrame
	for _, f := range frames {
		if f.typ == 6 && len(f.data) != 0 {
			crypto = append(crypto, f)
		}
	}
	sort.SliceStable(crypto, func(i, j int) bool { return crypto[i].offset < crypto[j].offset })
	var hello []byte
	for _, f := range crypto {
		if f.offset > uint64(len(hello)) {
			break
		}
		offset := int(f.offset)
		overlap := min(len(f.data), len(hello)-offset)
		if !bytes.Equal(hello[offset:offset+overlap], f.data[:overlap]) {
			return nil
		}
		n := min(len(f.data), 65535-offset)
		hello = append(hello, f.data[overlap:n]...)
		if len(hello) == 65535 {
			break
		}
	}
	if len(hello) < 4 || hello[0] != 1 {
		return nil
	}
	size := 4 + int(hello[1])<<16 + int(hello[2])<<8 + int(hello[3])
	if size > len(hello) {
		return nil
	}
	return hello[:size]
}

func quicCryptoCuts(frames []initialFrame, spec, order string) (cuts []int, hp hostPositions, resolved bool, err error) {
	hello := initialCryptoHello(frames)
	hp.start, hp.end = -1, -1
	if len(hello) > 0 {
		if parsed, e := tlsPositions(helloView{handshake: hello, wire: identity(len(hello))}); e == nil {
			hp = parsed
		}
	}
	if order == "sni_last" && hp.start < 0 {
		return nil, hp, false, nil
	}
	if spec == "" {
		return nil, hp, true, nil
	}
	// QUIC carries the handshake directly. Resolve both markers and signed
	// offsets in that stream; synthetic TLS headers would shift cuts at 16 KiB.
	for _, token := range strings.Split(spec, ",") {
		token = strings.TrimSpace(token)
		if n, e := strconv.Atoi(token); e == nil {
			if n <= 0 {
				return nil, hp, false, fmt.Errorf("desync: QUIC split offsets must be positive")
			}
			cuts = append(cuts, n)
			continue
		}
		if len(hello) == 0 || hp.start < 0 {
			return nil, hp, false, nil
		}
		base, delta := token, 0
		if i := strings.IndexAny(token, "+-"); i >= 0 {
			base = token[:i]
			var e error
			delta, e = strconv.Atoi(token[i:])
			if e != nil {
				return nil, hp, false, fmt.Errorf("desync: invalid QUIC split offset %q", token)
			}
		}
		var cut int
		switch base {
		case "sni", "host":
			cut = hp.start
		case "endhost":
			cut = hp.end
		case "sniext":
			cut = hp.extension
		case "extlen":
			cut = hp.extlen
		case "midsld":
			cut = hp.mid
		default:
			return nil, hp, false, fmt.Errorf("desync: invalid QUIC split marker %q", token)
		}
		cut += delta
		if cut <= 0 || cut >= len(hello) {
			return nil, hp, false, fmt.Errorf("desync: QUIC split %q outside ClientHello", token)
		}
		cuts = append(cuts, cut)
	}
	sort.Ints(cuts)
	return compactPositions(cuts), hp, true, nil
}

// Explicit permutations address actual fragments in stream-offset order, including
// pre-existing frame boundaries. Gaps and overlaps need ranges, not adjacent bounds.
func quicCryptoOrder(frames []initialFrame, spec string, hp hostPositions) ([]int, error) {
	order := identity(len(frames))
	sort.SliceStable(order, func(i, j int) bool { return frames[order[i]].offset < frames[order[j]].offset })
	switch spec {
	case "", "forward":
	case "reverse":
		for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
			order[i], order[j] = order[j], order[i]
		}
	case "sni_last":
		sni := func(i int) bool {
			f := frames[i]
			return f.offset < uint64(hp.end) && f.offset+uint64(len(f.data)) > uint64(hp.start)
		}
		sort.SliceStable(order, func(i, j int) bool { return !sni(order[i]) && sni(order[j]) })
	default:
		tokens := strings.Split(spec, ",")
		if len(tokens) != len(order) {
			return nil, fmt.Errorf("desync: quic_order requires a permutation of %d CRYPTO frames", len(order))
		}
		seen := make([]bool, len(order))
		permutation := make([]int, len(order))
		for i, token := range tokens {
			n, err := strconv.Atoi(strings.TrimSpace(token))
			if err != nil || n < 1 || n > len(order) || seen[n-1] {
				return nil, fmt.Errorf("desync: invalid quic_order permutation")
			}
			seen[n-1] = true
			permutation[i] = order[n-1]
		}
		order = permutation
	}
	return order, nil
}

func rewriteQUICCrypto(plain []byte, split, order string) ([]byte, bool, error) {
	frames, known, err := initialFrames(plain)
	if err != nil || !known {
		return plain, false, err
	}
	cuts, hp, resolved, err := quicCryptoCuts(frames, split, order)
	if err != nil || !resolved {
		return plain, false, err
	}
	var crypto []initialFrame
	counts := make([]int, len(frames))
	for i, f := range frames {
		if f.typ != 6 {
			continue
		}
		start := f.offset
		end := start + uint64(len(f.data))
		for _, cut := range cuts {
			if uint64(cut) <= start || uint64(cut) >= end {
				continue
			}
			crypto = append(crypto, initialFrame{offset: start, data: f.data[start-f.offset : uint64(cut)-f.offset]})
			counts[i]++
			start = uint64(cut)
		}
		crypto = append(crypto, initialFrame{offset: start, data: f.data[start-f.offset:]})
		counts[i]++
	}
	if len(crypto) == 0 {
		return plain, false, nil
	}
	indices, err := quicCryptoOrder(crypto, order, hp)
	if err != nil {
		return nil, false, err
	}
	var out []byte
	at := 0
	for i, f := range frames {
		switch f.typ {
		case 0: // Replaced with exactly enough padding when sealing.
		case 6:
			for j := 0; j < counts[i]; j++ {
				part := crypto[indices[at]]
				at++
				out = append(out, 6)
				out = appendQUICVarint(out, part.offset)
				out = appendQUICVarint(out, uint64(len(part.data)))
				out = append(out, part.data...)
			}
		default:
			out = append(out, f.raw...)
		}
	}
	return out, true, nil
}
