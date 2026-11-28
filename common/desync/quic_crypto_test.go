package desync

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"
)

func cryptoFrame(offset uint64, data []byte) []byte {
	b := appendQUICVarint([]byte{6}, offset)
	b = appendQUICVarint(b, uint64(len(data)))
	return append(b, data...)
}

func cryptoTestHello(t *testing.T) []byte {
	t.Helper()
	v, complete, err := clientHello(testHello(t, "www.example.com"))
	if err != nil || !complete {
		t.Fatalf("ClientHello: complete=%v err=%v", complete, err)
	}
	return v.handshake
}

func paddedTestInitial(t *testing.T, version uint32, pn uint64, plain []byte, size int) []byte {
	t.Helper()
	b := makeInitial(t, version, []byte("crypto-test-id"), pn, 2, plain, 2)
	if len(b) < size {
		plain = append(append([]byte(nil), plain...), make([]byte, size-len(b))...)
		b = makeInitial(t, version, []byte("crypto-test-id"), pn, 2, plain, 2)
	}
	return b
}

// Seal with the connection's original/Retry DCID while independently choosing
// the wire DCID and stable client SCID, as a client does after a server reply.
func connectionTestInitial(t *testing.T, version uint32, keyCID, dcid, scid []byte, pn uint64, pnBytes int, plain []byte) []byte {
	t.Helper()
	packet := makeInitial(t, version, keyCID, pn, pnBytes, plain, 2)
	h, err := initialPacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	header, body, nonce, _, hp, aead, err := unprotectInitial(packet, h, initialState{dcid: string(keyCID), largest: pn, seen: true})
	if err != nil {
		t.Fatal(err)
	}
	next := append([]byte(nil), header[:5]...)
	next = append(next, byte(len(dcid)))
	next = append(next, dcid...)
	next = append(next, byte(len(scid)))
	next = append(next, scid...)
	next = append(next, 0) // empty token
	next = append(next, header[h.lengthAt:]...)
	pnAt := len(next) - pnBytes
	packet = aead.Seal(append([]byte(nil), next...), nonce, body, next)
	var mask [16]byte
	hp.Encrypt(mask[:], packet[pnAt+4:pnAt+20])
	packet[0] ^= mask[0] & 15
	for i := pnAt; i < len(next); i++ {
		packet[i] ^= mask[i-pnAt+1]
	}
	return packet
}

func decodedCrypto(t *testing.T, packet []byte, state initialState, expectedPN uint64) ([]initialFrame, initialHeader) {
	t.Helper()
	h, err := initialPacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	_, plain, _, pn, _, _, err := unprotectInitial(packet, h, state)
	if err != nil || pn != expectedPN {
		t.Fatalf("authenticated packet pn=%d want=%d: %v", pn, expectedPN, err)
	}
	frames, known, err := initialFrames(plain)
	if err != nil || !known {
		t.Fatalf("frames known=%v: %v", known, err)
	}
	return frames, h
}

func assertCryptoBytes(t *testing.T, frames []initialFrame, hello []byte) []initialFrame {
	t.Helper()
	var crypto []initialFrame
	covered := make([]bool, len(hello))
	for _, f := range frames {
		if f.typ != 6 {
			continue
		}
		crypto = append(crypto, f)
		end := f.offset + uint64(len(f.data))
		if end > uint64(len(hello)) || !bytes.Equal(f.data, hello[f.offset:end]) {
			t.Fatalf("CRYPTO bytes changed at offset %d", f.offset)
		}
		for i := f.offset; i < end; i++ {
			covered[i] = true
		}
	}
	for i, present := range covered {
		if !present {
			t.Fatalf("missing handshake byte %d", i)
		}
	}
	return crypto
}

func TestQUICCryptoSplitVersionsAndOrdering(t *testing.T) {
	hello := cryptoTestHello(t)
	hp, err := tlsPositions(helloView{handshake: hello, wire: identity(len(hello))})
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []uint32{1, 0x6b3343cf, 0xff00001d} {
		for _, tc := range []struct {
			name, order string
			indices     []int
		}{
			{"default", "", []int{0, 1, 2}},
			{"forward", "forward", []int{0, 1, 2}},
			{"reverse", "reverse", []int{2, 1, 0}},
			{"sni_last", "sni_last", []int{0, 2, 1}},
			{"permutation", "3,1,2", []int{2, 0, 1}},
		} {
			t.Run(fmt.Sprintf("%x/%s", version, tc.name), func(t *testing.T) {
				// PING, ACK_ECN and CONNECTION_CLOSE must retain their exact bytes.
				prefix := []byte{1, 3, 5, 0, 0, 0, 1, 2, 3}
				suffix := []byte{0x1c, 0, 6, 3, 'b', 'y', 'e'}
				plain := append(append(append([]byte(nil), prefix...), cryptoFrame(0, hello)...), suffix...)
				tail := []byte("coalesced Handshake and 1-RTT ciphertext")
				original := append(paddedTestInitial(t, version, 73, plain, 2400), tail...)
				before := append([]byte(nil), original...)
				out, state, err := transformQUICInitial(original, 0, "host,endhost", tc.order, initialState{})
				if err != nil {
					t.Fatal(err)
				}
				if len(out) != len(original) || len(out) < 1200 || !bytes.Equal(original, before) {
					t.Fatal("size budget or input immutability violated")
				}
				frames, h := decodedCrypto(t, out, state, 73)
				if h.version != version || !bytes.Equal(out[h.end:], tail) {
					t.Fatal("version or coalesced tail changed")
				}
				crypto := assertCryptoBytes(t, frames, hello)
				bounds := []int{0, hp.start, hp.end, len(hello)}
				if len(crypto) != 3 {
					t.Fatalf("got %d CRYPTO frames", len(crypto))
				}
				for i, index := range tc.indices {
					if crypto[i].offset != uint64(bounds[index]) || len(crypto[i].data) != bounds[index+1]-bounds[index] {
						t.Fatalf("frame %d offset=%d length=%d", i, crypto[i].offset, len(crypto[i].data))
					}
				}
				var nonCrypto []byte
				for _, f := range frames {
					if f.typ != 0 && f.typ != 6 {
						nonCrypto = append(nonCrypto, f.raw...)
					}
				}
				if !bytes.Equal(nonCrypto, append(prefix, suffix...)) {
					t.Fatal("non-CRYPTO frame bytes changed")
				}
			})
		}
	}
}

func TestQUICCryptoAlreadyFragmentedHello(t *testing.T) {
	hello := cryptoTestHello(t)
	// Wire order differs from stream order, with a matching retransmitted overlap.
	plain := cryptoFrame(24, hello[24:80])
	plain = append(plain, 1) // PING between CRYPTO frames
	plain = append(plain, cryptoFrame(0, hello[:32])...)
	plain = append(plain, cryptoFrame(80, hello[80:])...)
	original := paddedTestInitial(t, 1, 9, plain, 2400)
	out, state, err := transformQUICInitial(original, 16, "host,endhost", "reverse", initialState{})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(original)+16 {
		t.Fatal("combined udplen did not add exactly 16 bytes")
	}
	frames, _ := decodedCrypto(t, out, state, 9)
	crypto := assertCryptoBytes(t, frames, hello)
	if len(crypto) != 5 {
		t.Fatalf("got %d fragments want 5", len(crypto))
	}
	for i := 1; i < len(crypto); i++ {
		if crypto[i].offset > crypto[i-1].offset {
			t.Fatal("fragments are not reversed by stream offset")
		}
	}
	var total int
	for _, f := range crypto {
		total += len(f.data)
	}
	if total != len(hello)+8 {
		t.Fatal("overlapping original CRYPTO bytes were dropped or duplicated")
	}
}

func TestQUICCryptoPartialHelloAndNumericOffsets(t *testing.T) {
	hello := cryptoTestHello(t)
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"prefix", cryptoFrame(0, hello[:80])},
		{"suffix", cryptoFrame(80, hello[80:])},
		{"gap", append(cryptoFrame(0, hello[:32]), cryptoFrame(40, hello[40:])...)},
		{"unrelated", cryptoFrame(0, []byte("not a ClientHello"))},
		{"empty", cryptoFrame(0, nil)},
		{"large offset", cryptoFrame(1<<40, []byte("suffix"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := paddedTestInitial(t, 1, 2, tc.data, 1200)
			for _, order := range []string{"reverse", "sni_last"} {
				out, state, err := transformQUICInitial(original, 0, "host", order, initialState{})
				if err != nil || !bytes.Equal(original, out) || !state.seen {
					t.Fatalf("unresolved semantic position: %v", err)
				}
			}
		})
	}
	plain := append(cryptoFrame(24, hello[24:64]), cryptoFrame(0, hello[:24])...)
	original := paddedTestInitial(t, 1, 3, plain, 1200)
	out, state, err := transformQUICInitial(original, 0, "30", "reverse", initialState{})
	if err != nil {
		t.Fatal(err)
	}
	frames, _ := decodedCrypto(t, out, state, 3)
	crypto := assertCryptoBytes(t, frames, hello[:64])
	var offsets []uint64
	for _, f := range crypto {
		offsets = append(offsets, f.offset)
	}
	if !reflect.DeepEqual(offsets, []uint64{30, 24, 0}) {
		t.Fatalf("numeric positions are not handshake offsets: %v", offsets)
	}
}

func TestQUICCryptoUnknownFramesAndMalformedInput(t *testing.T) {
	unknown := append(cryptoFrame(0, []byte("some handshake bytes")), 0x3f, 6, 0xff)
	original := paddedTestInitial(t, 1, 0, unknown, 1200)
	out, state, err := transformQUICInitial(original, 0, "2", "reverse", initialState{})
	if err != nil || !bytes.Equal(out, original) || !state.seen {
		t.Fatalf("unknown frame should make the payload opaque: %v", err)
	}
	out, state, err = transformQUICInitial(original, 8, "2", "reverse", initialState{})
	if err != nil || len(out) != len(original)+8 {
		t.Fatalf("opaque packet udplen: %v", err)
	}
	h, _ := initialPacket(out)
	_, plain, _, _, _, _, err := unprotectInitial(out, h, state)
	if err != nil || !bytes.Equal(plain[:len(unknown)], unknown) {
		t.Fatalf("opaque payload changed: %v", err)
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"truncated type", []byte{0xc0}},
		{"truncated offset", []byte{6, 0xc0}},
		{"truncated CRYPTO", []byte{6, 0, 0x3f, 1}},
		{"offset overflow", append(appendQUICVarint([]byte{6}, (1<<62)-1), 1, 42)},
		{"truncated ACK", []byte{2, 0xc0}},
		{"invalid ACK range", []byte{2, 0, 0, 0, 1}},
		{"excessive ACK ranges", []byte{2, 0, 0, 63, 0}},
		{"truncated close", []byte{0x1c, 0, 0, 63}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Prefix enough PINGs for the header protection sample without hiding
			// malformed trailing varints behind padding bytes.
			plain := append(bytes.Repeat([]byte{1}, 8), tc.data...)
			original := makeInitial(t, 1, []byte("bad-frame"), 0, 1, plain, 2)
			if _, _, err := transformQUICInitial(original, 0, "2", "reverse", initialState{}); err == nil {
				t.Fatal("malformed frame accepted")
			}
		})
	}
	corrupted := append([]byte(nil), original...)
	corrupted[len(corrupted)-1] ^= 1
	if _, _, err := transformQUICInitial(corrupted, 0, "2", "reverse", initialState{}); err == nil {
		t.Fatal("unauthenticated Initial transformed")
	}
}

func TestQUICCryptoSizeBudgetAndPermutation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		size  int
		extra int
		order string
		fail  bool
	}{
		{"small may grow", 40, 0, "reverse", false},
		{"padding funds split", 1200, 0, "reverse", false},
		{"invalid permutation", 1200, 0, "1,1,3", true},
		{"wrong permutation size", 1200, 0, "2,1", true},
		{"UDP overflow", 1200, 65507, "reverse", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := paddedTestInitial(t, 1, 0, cryptoFrame(0, []byte("0123456789")), tc.size)
			out, state, err := transformQUICInitial(original, tc.extra, "2,5", tc.order, initialState{})
			if (err != nil) != tc.fail {
				t.Fatalf("err=%v want failure=%v", err, tc.fail)
			}
			if err == nil {
				frames, _ := decodedCrypto(t, out, state, 0)
				assertCryptoBytes(t, frames, []byte("0123456789"))
				if len(original) >= 1200 && len(out) != len(original) {
					t.Fatal("padded datagram inflated")
				}
			}
		})
	}
	// An Initial already at its MTU without padding must fail before sending,
	// unless udplen explicitly provides room for the new CRYPTO headers.
	original := paddedTestInitial(t, 1, 0, cryptoFrame(0, bytes.Repeat([]byte{42}, 1400)), 0)
	if _, _, err := transformQUICInitial(original, 0, "2,5", "reverse", initialState{}); err == nil {
		t.Fatal("split implicitly exceeded original MTU")
	}
	out, _, err := transformQUICInitial(original, 32, "2,5", "reverse", initialState{})
	if err != nil || len(out) != len(original)+32 {
		t.Fatalf("explicit size budget: %v", err)
	}
}

func FuzzQUICCryptoFrames(f *testing.F) {
	f.Add([]byte{6, 0, 4, 1, 0, 0, 0})
	f.Add([]byte{2, 0, 0, 63, 0})
	f.Fuzz(func(t *testing.T, plain []byte) {
		if len(plain) > 65507 {
			return
		}
		_, _, _ = rewriteQUICCrypto(plain, "host,endhost", "sni_last")
		_, _, _ = rewriteQUICCrypto(plain, "2,30", "reverse")
	})
}

func TestQUICCryptoCIDChangeRetryAndPacketNumberWrap(t *testing.T) {
	originalCID := []byte("crypto-test-id")
	peerCID := []byte("server-test-id")
	state := initialState{}
	for _, pn := range []uint64{65534, 65535, 65536, 65537} {
		packet := paddedTestInitial(t, 1, pn, cryptoFrame(0, []byte("0123456789")), 1200)
		if pn >= 65536 {
			// The peer changes the wire DCID, but Initial protection still uses
			// the original DCID until Retry. Seal independently with those keys.
			h, err := initialPacket(packet)
			if err != nil {
				t.Fatal(err)
			}
			header, plain, nonce, _, hp, aead, err := unprotectInitial(packet, h, state)
			if err != nil {
				t.Fatal(err)
			}
			copy(header[6:6+len(peerCID)], peerCID)
			packet = aead.Seal(append([]byte(nil), header...), nonce, plain, header)
			var mask [16]byte
			hp.Encrypt(mask[:], packet[h.pnAt+4:h.pnAt+20])
			packet[0] ^= mask[0] & 15
			for i := h.pnAt; i < len(header); i++ {
				packet[i] ^= mask[i-h.pnAt+1]
			}
		}
		out, next, err := transformQUICInitial(packet, 0, "2,5", "reverse", state)
		if err != nil {
			t.Fatalf("PN %d: %v", pn, err)
		}
		state = next
		frames, h := decodedCrypto(t, out, state, pn)
		assertCryptoBytes(t, frames, []byte("0123456789"))
		if state.dcid != string(originalCID) || state.largest != pn {
			t.Fatalf("lost original key state at PN %d: %+v", pn, state)
		}
		if pn >= 65536 && !bytes.Equal(h.dcid, peerCID) {
			t.Fatal("wire destination CID changed")
		}
	}
	// A post-Retry Initial is sealed with a new destination CID and a fresh
	// number space, so authentication must retry with the new public keys.
	retry := makeInitial(t, 1, []byte("retry-test-id"), 0, 2, append(cryptoFrame(0, []byte("0123456789")), make([]byte, 1200)...), 2)
	out, next, err := transformQUICInitial(retry, 0, "2,5", "reverse", state)
	if err != nil {
		t.Fatal(err)
	}
	frames, _ := decodedCrypto(t, out, next, 0)
	assertCryptoBytes(t, frames, []byte("0123456789"))
	if next.dcid != "retry-test-id" || next.largest != 0 {
		t.Fatalf("Retry did not reset key state: %+v", next)
	}
}

func TestQUICCryptoSemanticMarkersUseHandshakeOffsets(t *testing.T) {
	hello := cryptoTestHello(t)
	hp, err := tlsPositions(helloView{handshake: hello, wire: identity(len(hello))})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		want int
	}{
		{"sni", hp.start},
		{"host+1", hp.start + 1},
		{"endhost-1", hp.end - 1},
		{"sniext+1", hp.extension + 1},
		{"extlen", hp.extlen},
		{"midsld-1", hp.mid - 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := paddedTestInitial(t, 1, 1, cryptoFrame(0, hello), 2400)
			out, state, err := transformQUICInitial(original, 0, tc.name, "", initialState{})
			if err != nil {
				t.Fatal(err)
			}
			frames, _ := decodedCrypto(t, out, state, 1)
			crypto := assertCryptoBytes(t, frames, hello)
			if len(crypto) != 2 || len(crypto[0].data) != tc.want || crypto[1].offset != uint64(tc.want) {
				t.Fatalf("semantic position did not convert to handshake offset %d", tc.want)
			}
		})
	}
}

func TestQUICCryptoMarkerOffsetsAcrossSyntheticRecordBoundary(t *testing.T) {
	hello := cryptoTestHello(t)
	hp, err := tlsPositions(helloView{handshake: hello, wire: identity(len(hello))})
	if err != nil {
		t.Fatal(err)
	}
	padding := 16380 - hp.start - 4
	if padding < 0 {
		t.Fatal("unexpectedly large fixture prefix")
	}
	ext := append([]byte{0, 21, byte(padding >> 8), byte(padding)}, make([]byte, padding)...)
	large := append(append(append([]byte(nil), hello[:hp.extension]...), ext...), hello[hp.extension:]...)
	binary.BigEndian.PutUint16(large[hp.extlen:], uint16(int(binary.BigEndian.Uint16(hello[hp.extlen:]))+len(ext)))
	n := len(large) - 4
	large[1], large[2], large[3] = byte(n>>16), byte(n>>8), byte(n)
	frames := []initialFrame{{typ: 6, data: large}}
	for _, tc := range []struct {
		name string
		want int
	}{{"host+8", 16388}, {"host+12", 16392}, {"endhost-8", 16387}} {
		t.Run(tc.name, func(t *testing.T) {
			cuts, _, resolved, err := quicCryptoCuts(frames, tc.name, "reverse")
			if err != nil || !resolved || len(cuts) != 1 || cuts[0] != tc.want {
				t.Fatalf("CRYPTO marker resolved through nonexistent TLS headers: %v, %v", cuts, err)
			}
		})
	}
}

func TestQUICCryptoPreservesPacketNumberWidths(t *testing.T) {
	for width := 1; width <= 4; width++ {
		t.Run(fmt.Sprintf("PN%d", width), func(t *testing.T) {
			original := makeInitial(t, 1, []byte("packet-width"), 23, width, append(cryptoFrame(0, []byte("0123456789")), make([]byte, 1200)...), 2)
			out, state, err := transformQUICInitial(original, 0, "2,5", "reverse", initialState{})
			if err != nil {
				t.Fatal(err)
			}
			h, err := initialPacket(out)
			if err != nil {
				t.Fatal(err)
			}
			header, _, _, pn, _, _, err := unprotectInitial(out, h, state)
			if err != nil || pn != 23 || len(header)-h.pnAt != width {
				t.Fatalf("PN length or value changed: pn=%d width=%d err=%v", pn, len(header)-h.pnAt, err)
			}
		})
	}
}
