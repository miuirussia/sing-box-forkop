package desync

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

type fakeTLSExtension struct {
	typeID uint16
	data   []byte
}

type fakeTLSHello struct {
	handshake  []byte
	sessionEnd int
	extStart   int
	extensions []fakeTLSExtension
}

// transformFakeTLS only changes a fake. With all transformations disabled even
// non-TLS custom payloads pass through verbatim. Active transformations emit
// exactly one ClientHello, never the rest of the captured connection.
func transformFakeTLS(fake []byte, randomize bool, targetSize int, template string) ([]byte, error) {
	if targetSize < 0 || targetSize > 60000 {
		return nil, fmt.Errorf("desync: fake TLS size must be between 0 and 60000")
	}
	if template != "" && template != "original" && template != "compact" {
		return nil, fmt.Errorf("desync: unknown fake TLS template %q", template)
	}
	if !randomize && targetSize == 0 && template != "compact" {
		return fake, nil
	}
	v, complete, err := clientHello(fake)
	if err != nil {
		return nil, fmt.Errorf("desync: fake TLS requires a TLS ClientHello: %w", err)
	}
	if !complete {
		return nil, fmt.Errorf("desync: fake TLS requires a complete TLS ClientHello")
	}
	h, err := parseFakeTLSHello(v.handshake)
	if err != nil {
		return nil, err
	}
	extensions := make([]fakeTLSExtension, 0, len(h.extensions)+1)
	for _, ext := range h.extensions {
		if template == "compact" {
			switch ext.typeID {
			case 0, 10, 13, 43, 45, 51:
			default:
				// In particular, remove the entire PSK extension (identities
				// and binders) together with early_data.
				continue
			}
		}
		if targetSize != 0 && ext.typeID == 21 {
			continue
		}
		extensions = append(extensions, ext)
	}
	// The parser owns a copy, so randomizing these slices cannot change the
	// caller's real flight or custom fake buffer.
	if randomize {
		if _, err = rand.Read(h.handshake[6:38]); err != nil {
			return nil, fmt.Errorf("desync: randomize fake TLS Random: %w", err)
		}
		if _, err = rand.Read(h.handshake[39:h.sessionEnd]); err != nil {
			return nil, fmt.Errorf("desync: randomize fake TLS SessionID: %w", err)
		}
		for _, ext := range extensions {
			if ext.typeID != 51 {
				continue
			}
			for p := 2; p < len(ext.data); {
				n := int(binary.BigEndian.Uint16(ext.data[p+2:]))
				if _, err = rand.Read(ext.data[p+4 : p+4+n]); err != nil {
					return nil, fmt.Errorf("desync: randomize fake TLS key share: %w", err)
				}
				p += 4 + n
			}
		}
	}
	base := append([]byte(nil), h.handshake[:h.extStart]...)
	hasExtensions := h.extStart < len(h.handshake) || len(extensions) != 0
	extSize := 0
	for _, ext := range extensions {
		extSize += 4 + len(ext.data)
	}
	baseSize := len(base) + extSize
	if hasExtensions {
		baseSize += 2
	}
	records := (baseSize + 16383) / 16384
	padding := -1
	if targetSize != 0 {
		found := false
		// Account for every record header. A boundary target can require
		// splitting a little earlier than 16384 to fit exactly.
		for count := 1; count <= 4; count++ {
			payloadSize := targetSize - 5*count
			if payloadSize < baseSize || payloadSize > 16384*count || payloadSize < count {
				continue
			}
			delta := payloadSize - baseSize
			paddingOverhead := 4
			if !hasExtensions {
				paddingOverhead += 2
			}
			if delta != 0 && delta < paddingOverhead {
				continue
			}
			records = count
			if delta != 0 {
				padding = delta - paddingOverhead
				hasExtensions = true
			}
			found = true
			break
		}
		if !found {
			return nil, fmt.Errorf("desync: fake TLS target size %d cannot fit ClientHello and padding (minimum %d)", targetSize, baseSize+5*((baseSize+16383)/16384))
		}
	}
	if padding >= 0 {
		pad := fakeTLSExtension{21, make([]byte, padding)}
		// RFC 8446 requires pre_shared_key to remain the last extension.
		if len(extensions) > 0 && extensions[len(extensions)-1].typeID == 41 {
			last := extensions[len(extensions)-1]
			extensions[len(extensions)-1] = pad
			extensions = append(extensions, last)
		} else {
			extensions = append(extensions, pad)
		}
		extSize += 4 + padding
	}
	if extSize > 65535 {
		return nil, fmt.Errorf("desync: fake TLS extensions exceed 65535 bytes")
	}
	if hasExtensions {
		base = binary.BigEndian.AppendUint16(base, uint16(extSize))
		for _, ext := range extensions {
			base = binary.BigEndian.AppendUint16(base, ext.typeID)
			base = binary.BigEndian.AppendUint16(base, uint16(len(ext.data)))
			base = append(base, ext.data...)
		}
	}
	n := len(base) - 4
	base[1], base[2], base[3] = byte(n>>16), byte(n>>8), byte(n)
	out := make([]byte, 0, len(base)+5*records)
	for remaining := records; remaining > 0; remaining-- {
		n = min(16384, len(base)-(remaining-1))
		out = append(out, 22, fake[1], fake[2], byte(n>>8), byte(n))
		out = append(out, base[:n]...)
		base = base[n:]
	}
	return out, nil
}

func parseFakeTLSHello(handshake []byte) (fakeTLSHello, error) {
	h := fakeTLSHello{handshake: append([]byte(nil), handshake...)}
	b := h.handshake
	fail := func(detail string) (fakeTLSHello, error) {
		return fakeTLSHello{}, fmt.Errorf("desync: malformed fake TLS ClientHello: %s", detail)
	}
	if len(b) < 39 || b[4] != 3 || b[38] > 32 {
		return fail("invalid version, Random or SessionID")
	}
	h.sessionEnd = 39 + int(b[38])
	p := h.sessionEnd
	if len(b)-p < 2 {
		return fail("truncated cipher suites")
	}
	n := int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	if n == 0 || n%2 != 0 || n > len(b)-p {
		return fail("invalid cipher suites vector")
	}
	p += n
	if p >= len(b) || b[p] == 0 || int(b[p]) > len(b)-p-1 {
		return fail("invalid compression methods vector")
	}
	p += 1 + int(b[p])
	h.extStart = p
	if p == len(b) { // TLS 1.2 and earlier can omit extensions entirely.
		return h, nil
	}
	if len(b)-p < 2 || int(binary.BigEndian.Uint16(b[p:])) != len(b)-p-2 {
		return fail("invalid extensions length")
	}
	p += 2
	seen := make(map[uint16]bool)
	for p < len(b) {
		if len(b)-p < 4 {
			return fail("truncated extension header")
		}
		typeID := binary.BigEndian.Uint16(b[p:])
		n = int(binary.BigEndian.Uint16(b[p+2:]))
		p += 4
		if n > len(b)-p || seen[typeID] {
			return fail("truncated or duplicate extension")
		}
		seen[typeID] = true
		data := b[p : p+n]
		if err := validateFakeTLSExtension(typeID, data); err != nil {
			return fail(err.Error())
		}
		p += n
		if typeID == 41 && p != len(b) {
			return fail("pre_shared_key must be the last extension")
		}
		h.extensions = append(h.extensions, fakeTLSExtension{typeID, data})
	}
	if seen[41] && !seen[45] {
		return fail("pre_shared_key requires PSK key exchange modes")
	}
	return h, nil
}

func validateFakeTLSExtension(typeID uint16, b []byte) error {
	invalid := func() error { return fmt.Errorf("invalid extension %d", typeID) }
	switch typeID {
	case 0, 10, 13, 50, 51:
		if len(b) < 2 || int(binary.BigEndian.Uint16(b)) != len(b)-2 {
			return invalid()
		}
		switch typeID {
		case 0:
			if len(b) == 2 {
				return invalid()
			}
			seen := make(map[byte]bool)
			for p := 2; p < len(b); {
				if len(b)-p < 3 || seen[b[p]] {
					return invalid()
				}
				seen[b[p]] = true
				n := int(binary.BigEndian.Uint16(b[p+1:]))
				p += 3
				if n == 0 || n > len(b)-p {
					return invalid()
				}
				p += n
			}
		case 51:
			seen := make(map[uint16]bool)
			for p := 2; p < len(b); {
				if len(b)-p < 4 {
					return invalid()
				}
				group := binary.BigEndian.Uint16(b[p:])
				n := int(binary.BigEndian.Uint16(b[p+2:]))
				p += 4
				if n == 0 || n > len(b)-p || seen[group] {
					return invalid()
				}
				seen[group] = true
				p += n
			}
		default:
			if len(b) < 4 || len(b)%2 != 0 {
				return invalid()
			}
		}
	case 43, 45:
		if len(b) < 2 || int(b[0]) != len(b)-1 || (typeID == 43 && (b[0] < 2 || b[0]%2 != 0)) {
			return invalid()
		}
	case 21:
		for _, v := range b {
			if v != 0 {
				return invalid()
			}
		}
	case 42:
		if len(b) != 0 {
			return invalid()
		}
	case 41:
		if len(b) < 2 {
			return invalid()
		}
		end := 2 + int(binary.BigEndian.Uint16(b))
		if end > len(b)-2 || end == 2 {
			return invalid()
		}
		identities := 0
		for p := 2; p < end; identities++ {
			if end-p < 2 {
				return invalid()
			}
			n := int(binary.BigEndian.Uint16(b[p:]))
			p += 2
			if n == 0 || n > end-p-4 {
				return invalid()
			}
			p += n + 4
		}
		if int(binary.BigEndian.Uint16(b[end:])) != len(b)-end-2 {
			return invalid()
		}
		binders := 0
		for p := end + 2; p < len(b); binders++ {
			n := int(b[p])
			p++
			if n < 32 || n > len(b)-p {
				return invalid()
			}
			p += n
		}
		if identities != binders {
			return invalid()
		}
	}
	return nil
}
