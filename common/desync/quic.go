package desync

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Initial protection keys are public, derived from the DCID (RFC9001/9369).
// Only Initial can be resized without endpoint traffic secrets. Handshake,
// 0-RTT and 1-RTT packets coalesced after it remain byte-for-byte unchanged.
type initialHeader struct {
	version                          uint32
	dcid, scid                       []byte
	lengthAt, lengthBytes, pnAt, end int
	length                           uint64
}

func readQUICVarint(b []byte, p int) (uint64, int, error) {
	if p >= len(b) {
		return 0, 0, io.ErrUnexpectedEOF
	}
	n := 1 << uint(b[p]>>6)
	if n > len(b)-p {
		return 0, 0, io.ErrUnexpectedEOF
	}
	v := uint64(b[p] & 63)
	for _, x := range b[p+1 : p+n] {
		v = v<<8 | uint64(x)
	}
	return v, n, nil
}
func initialPacket(b []byte) (h initialHeader, err error) {
	bad := func() (initialHeader, error) { return initialHeader{}, fmt.Errorf("desync: invalid QUIC Initial") }
	if len(b) < 7 || b[0]&0xc0 != 0xc0 {
		return bad()
	}
	h.version = binary.BigEndian.Uint32(b[1:])
	typ := (b[0] >> 4) & 3
	if !((h.version == 1 || h.version == 0xff00001d) && typ == 0 || h.version == 0x6b3343cf && typ == 1) {
		return bad()
	}
	p := 5
	n := int(b[p])
	p++
	if n == 0 || n > 20 || p+n >= len(b) {
		return bad()
	}
	h.dcid = b[p : p+n]
	p += n
	n = int(b[p])
	p++
	if n > 20 || p+n >= len(b) {
		return bad()
	}
	h.scid = b[p : p+n]
	p += n
	token, k, e := readQUICVarint(b, p)
	if e != nil {
		return bad()
	}
	p += k
	if token > uint64(len(b)-p) {
		return bad()
	}
	p += int(token)
	h.lengthAt = p
	h.length, h.lengthBytes, err = readQUICVarint(b, p)
	if err != nil {
		return bad()
	}
	p += h.lengthBytes
	h.pnAt = p
	if h.length > uint64(len(b)-p) || h.length < 20 {
		return bad()
	}
	h.end = p + int(h.length)
	return h, nil
}
func quicInitial(b []byte) bool { _, err := initialPacket(b); return err == nil }
func initialSecrets(h initialHeader) (cipher.AEAD, cipher.Block, []byte, error) {
	salt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	prefix := "quic"
	if h.version == 0x6b3343cf {
		salt = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
		prefix = "quicv2"
	} else if h.version == 0xff00001d {
		salt = []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99}
	}
	secret := hkdf.Extract(sha256.New, h.dcid, salt)
	expand := func(secret []byte, label string, n int) []byte {
		label = "tls13 " + label
		info := []byte{byte(n >> 8), byte(n), byte(len(label))}
		info = append(info, label...)
		info = append(info, 0)
		out := make([]byte, n)
		_, _ = io.ReadFull(hkdf.Expand(sha256.New, secret, info), out)
		return out
	}
	client := expand(secret, "client in", 32)
	key := expand(client, prefix+" key", 16)
	iv := expand(client, prefix+" iv", 12)
	hp, err := aes.NewCipher(expand(client, prefix+" hp", 16))
	if err != nil {
		return nil, nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	return gcm, hp, iv, err
}

type initialState struct {
	dcid    string
	largest uint64
	seen    bool
}

func initialNumber(truncated uint64, n int, largest uint64, seen bool) uint64 {
	if !seen {
		return truncated
	}
	expected := largest + 1
	window := uint64(1) << uint(n*8)
	half := window / 2
	candidate := (expected &^ (window - 1)) | truncated
	if candidate+half <= expected && candidate < (uint64(1)<<62)-window {
		candidate += window
	} else if candidate > expected+half && candidate >= window {
		candidate -= window
	}
	return candidate
}
func unprotectInitial(b []byte, h initialHeader, state initialState) (header, plain, nonce []byte, pn uint64, hp cipher.Block, aead cipher.AEAD, err error) {
	keyHeader := h
	if state.seen {
		keyHeader.dcid = []byte(state.dcid)
	}
	aead, hp, iv, err := initialSecrets(keyHeader)
	if err != nil {
		return nil, nil, nil, 0, nil, nil, err
	}
	mask := make([]byte, 16)
	hp.Encrypt(mask, b[h.pnAt+4:h.pnAt+20])
	first := b[0] ^ (mask[0] & 15)
	pnLen := int(first&3) + 1
	if h.length < uint64(pnLen+16) {
		return nil, nil, nil, 0, nil, nil, fmt.Errorf("desync: truncated protected Initial")
	}
	header = append([]byte(nil), b[:h.pnAt+pnLen]...)
	header[0] = first
	var truncated uint64
	for i := 0; i < pnLen; i++ {
		header[h.pnAt+i] ^= mask[i+1]
		truncated = truncated<<8 | uint64(header[h.pnAt+i])
	}
	pn = initialNumber(truncated, pnLen, state.largest, state.seen)
	nonce = append([]byte(nil), iv...)
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], pn)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= encoded[i]
	}
	plain, err = aead.Open(nil, nonce, b[h.pnAt+pnLen:h.end], header)
	if err != nil {
		return nil, nil, nil, 0, nil, nil, fmt.Errorf("desync: cannot authenticate QUIC Initial: %w", err)
	}
	return header, plain, nonce, pn, hp, aead, nil
}
func padQUICInitial(b []byte, extra int, state initialState) ([]byte, initialState, error) {
	return transformQUICInitial(b, extra, "", "", state)
}

// transformQUICInitial authenticates once for both CRYPTO rewriting and udplen.
// It never creates a packet number or touches packets coalesced after Initial.
func transformQUICInitial(b []byte, extra int, split, order string, state initialState) ([]byte, initialState, error) {
	if extra < 0 || extra > 65507 || len(b) > 65507-extra {
		return nil, state, fmt.Errorf("desync: padded QUIC exceeds UDP size")
	}
	h, err := initialPacket(b)
	if err != nil {
		return nil, state, err
	}
	originalState := state
	header, plain, nonce, pn, hp, aead, err := unprotectInitial(b, h, state)
	if err != nil && state.seen && state.dcid != string(h.dcid) {
		// Retry changes the protection key, not this connection's packet numbers.
		state.dcid = string(h.dcid)
		header, plain, nonce, pn, hp, aead, err = unprotectInitial(b, h, state)
		if err != nil && len(h.scid) == 0 {
			// Zero-SCID sockets support one connection at a time; a fresh
			// connection can reuse the same destination with a new number space.
			state = initialState{}
			header, plain, nonce, pn, hp, aead, err = unprotectInitial(b, h, state)
		}
	}
	if err != nil {
		return nil, originalState, err
	}
	if !state.seen {
		state.dcid = string(h.dcid)
	}
	if !state.seen || pn > state.largest {
		state.largest = pn
	}
	state.seen = true

	changed := false
	if split != "" || order != "" {
		plain, changed, err = rewriteQUICCrypto(plain, split, order)
		if err != nil {
			return nil, originalState, err
		}
	}
	if !changed && extra == 0 {
		return b, state, nil
	}

	pnLen := len(header) - h.pnAt
	tail := b[h.end:]
	target := len(b) + extra
	// Existing padding pays for new frame headers first. Small synthetic Initials
	// may grow up to 1200, but never implicitly enlarge an existing MTU-sized
	// datagram. udplen explicitly supplies additional space above that budget.
	limit := min(65507, max(1200, target))
	width := h.lengthBytes
	for {
		minimum := h.lengthAt + width + pnLen + len(plain) + aead.Overhead() + len(tail)
		if minimum > target {
			if !changed {
				return nil, originalState, fmt.Errorf("desync: udplen too small for QUIC length-field growth")
			}
			if minimum > limit {
				return nil, originalState, fmt.Errorf("desync: insufficient QUIC padding for CRYPTO split within datagram size budget")
			}
			target = minimum
		}
		length := target - len(tail) - h.lengthAt - width
		if uint64(length) < uint64(1)<<uint(width*8-2) {
			break
		}
		width *= 2
		if width > 8 {
			return nil, originalState, fmt.Errorf("desync: QUIC length overflow")
		}
	}
	length := target - len(tail) - h.lengthAt - width
	padding := length - pnLen - aead.Overhead() - len(plain)
	if padding < 0 {
		return nil, originalState, fmt.Errorf("desync: udplen too small for QUIC length-field growth")
	}
	newHeader := append([]byte(nil), header[:h.lengthAt]...)
	newHeader = appendQUICVarintWidth(newHeader, uint64(length), width)
	pnAt := len(newHeader)
	newHeader = append(newHeader, header[h.pnAt:]...)
	plain = append(plain, make([]byte, padding)...)
	out := aead.Seal(append([]byte(nil), newHeader...), nonce, plain, newHeader)
	mask := make([]byte, 16)
	hp.Encrypt(mask, out[pnAt+4:pnAt+20])
	out[0] ^= mask[0] & 15
	for i := pnAt; i < len(newHeader); i++ {
		out[i] ^= mask[i-pnAt+1]
	}
	out = append(out, tail...)
	return out, state, nil
}

func appendQUICVarintWidth(b []byte, value uint64, width int) []byte {
	at := len(b)
	b = append(b, make([]byte, width)...)
	for i := at + width - 1; i >= at; i-- {
		b[i] = byte(value)
		value >>= 8
	}
	switch width {
	case 2:
		b[at] |= 0x40
	case 4:
		b[at] |= 0x80
	case 8:
		b[at] |= 0xc0
	}
	return b
}

func appendQUICVarint(b []byte, value uint64) []byte {
	width := 1
	for value >= uint64(1)<<uint(width*8-2) {
		width *= 2
	}
	return appendQUICVarintWidth(b, value, width)
}
func fakeQUICInitial(b []byte) []byte {
	h, err := initialPacket(b)
	if err != nil {
		return nil
	}
	fake := append([]byte(nil), b[:h.end]...)
	fake[len(fake)-1] ^= 0xff
	if len(fake) < 1200 {
		fake = append(fake, make([]byte, 1200-len(fake))...)
	}
	return fake
}
