package desync

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// makeInitial seals an independent test Initial using the public initial keys.
func makeInitial(t *testing.T, version uint32, dcid []byte, pn uint64, pnBytes int, plain []byte, width int) []byte {
	t.Helper()
	first := byte(0xc0) | byte(pnBytes-1)
	if version == 0x6b3343cf {
		first |= 0x10
	}
	b := []byte{first, 0, 0, 0, 0, byte(len(dcid))}
	binary.BigEndian.PutUint32(b[1:], version)
	b = append(b, dcid...)
	b = append(b, 0, 0)
	lengthAt := len(b)
	length := pnBytes + len(plain) + 16
	encoded := make([]byte, width)
	value := length
	for i := width - 1; i >= 0; i-- {
		encoded[i] = byte(value)
		value >>= 8
	}
	if width == 2 {
		encoded[0] |= 0x40
	}
	b = append(b, encoded...)
	pnAt := len(b)
	for i := pnBytes - 1; i >= 0; i-- {
		b = append(b, byte(pn>>uint(i*8)))
	}
	h := initialHeader{version: version, dcid: dcid, lengthAt: lengthAt, lengthBytes: width, pnAt: pnAt, length: uint64(length)}
	aead, hp, iv, err := initialSecrets(h)
	if err != nil {
		t.Fatal(err)
	}
	var encodedPN [8]byte
	binary.BigEndian.PutUint64(encodedPN[:], pn)
	for i := 0; i < 8; i++ {
		iv[4+i] ^= encodedPN[i]
	}
	out := aead.Seal(append([]byte(nil), b...), iv, plain, b)
	mask := make([]byte, 16)
	hp.Encrypt(mask, out[pnAt+4:pnAt+20])
	out[0] ^= mask[0] & 15
	for i := 0; i < pnBytes; i++ {
		out[pnAt+i] ^= mask[i+1]
	}
	return out
}
func TestQUICInitialResizeVersionsAndVarintBoundary(t *testing.T) {
	for _, tc := range []struct {
		name                string
		version             uint32
		plain, extra, width int
	}{{"v1", 1, 60, 32, 2}, {"v2", 0x6b3343cf, 60, 17, 2}, {"draft29", 0xff00001d, 60, 3, 2}, {"length-field-growth", 1, 42, 8, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			plain := append([]byte{1}, make([]byte, tc.plain-1)...)
			original := makeInitial(t, tc.version, []byte("initial-id"), 0, 1, plain, tc.width)
			tail := []byte("coalesced protected application data")
			original = append(original, tail...)
			padded, state, err := padQUICInitial(original, tc.extra, initialState{})
			if err != nil {
				t.Fatal(err)
			}
			if len(padded) != len(original)+tc.extra {
				t.Fatalf("grew by %d want%d", len(padded)-len(original), tc.extra)
			}
			h, err := initialPacket(padded)
			if err != nil {
				t.Fatal(err)
			}
			_, decoded, _, _, _, _, err := unprotectInitial(padded, h, state)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decoded[:len(plain)], plain) {
				t.Fatal("Initial frame bytes changed")
			}
			for _, x := range decoded[len(plain):] {
				if x != 0 {
					t.Fatal("non-PADDING appended")
				}
			}
			if !bytes.Equal(padded[h.end:], tail) {
				t.Fatal("coalesced protected application packet changed")
			}
			fake := fakeQUICInitial(original)
			if bytes.Contains(fake, tail) {
				t.Fatal("coalesced data copied into fake")
			}
			fh, err := initialPacket(fake)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, _, _, _, err = unprotectInitial(fake, fh, initialState{}); err == nil {
				t.Fatal("fake still authenticates")
			}
		})
	}
}
func TestQUICPacketNumberWrapAndPeerCID(t *testing.T) {
	dcid := []byte("first-id")
	state := initialState{}
	for _, pn := range []uint64{254, 255, 256, 257} {
		b := makeInitial(t, 1, dcid, pn, 1, make([]byte, 40), 2)
		_, next, err := padQUICInitial(b, 8, state)
		if err != nil {
			t.Fatalf("pn%d: %v", pn, err)
		}
		state = next
		if state.largest != pn {
			t.Fatalf("PN reconstructed %d want%d", state.largest, pn)
		}
	}
}
func FuzzInitialResize(f *testing.F) {
	f.Add([]byte{0xc0, 0, 0, 0, 1, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65507 {
			return
		}
		_, _, _ = padQUICInitial(b, 8, initialState{})
	})
}
