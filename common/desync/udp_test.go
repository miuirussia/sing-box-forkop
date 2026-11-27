package desync

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

func TestUDPPerDestinationCounters(t *testing.T) {
	o := option.DesyncOptions{Mode: "none", UDPMode: "stun", UDPRepeats: 2, UDPOutRange: "2:2", UDPFakePayload: base64.StdEncoding.EncodeToString([]byte("FAKE"))}
	s, err := newUDPState(context.Background(), o, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer s.stop()
	real := make([]byte, 20)
	real[1] = 1
	binary.BigEndian.PutUint32(real[4:], 0x2112a442)
	totals := map[string]int{}
	for _, key := range []string{"a", "b", "a", "b", "a"} {
		_, err := s.write(real, key, nil, func(b []byte) (int, error) {
			if string(b) == "FAKE" {
				totals[key]++
			}
			return len(b), nil
		}, func(_ int, send func([]byte) (int, error), burst func(func([]byte) (int, error)) error) error {
			return burst(send)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if totals["a"] != 2 || totals["b"] != 2 {
		t.Fatal(totals)
	}
}
func TestSTUNPaddingPreservesIntegrityAndFingerprint(t *testing.T) {
	real := make([]byte, 20)
	real[1] = 1
	binary.BigEndian.PutUint32(real[4:], 0x2112a442)
	padded, err := padSTUN(real, 12)
	if err != nil {
		t.Fatal(err)
	}
	if len(padded) != 32 || binary.BigEndian.Uint16(padded[2:]) != 12 || binary.BigEndian.Uint16(padded[20:]) != 0x26 {
		t.Fatal("invalid STUN padding")
	}
	if !bytes.Equal(padded[4:20], real[4:20]) {
		t.Fatal("STUN transaction changed")
	}

	// MESSAGE-INTEGRITY bytes and their authenticated prefix survive padding.
	authenticated := append(append([]byte(nil), real...), 0, 8, 0, 20)
	binary.BigEndian.PutUint16(authenticated[2:], 24)
	mac := hmac.New(sha1.New, []byte("test-password"))
	mac.Write(authenticated[:20])
	authenticated = append(authenticated, mac.Sum(nil)...)
	fingerprint := len(authenticated)
	authenticated = append(authenticated, 0x80, 0x28, 0, 4, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(authenticated[2:], uint16(len(authenticated)-20))
	binary.BigEndian.PutUint32(authenticated[fingerprint+4:], crc32.ChecksumIEEE(authenticated[:fingerprint])^0x5354554e)
	padded, err = padSTUN(authenticated, 12)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(padded[20:44], authenticated[20:44]) {
		t.Fatal("MESSAGE-INTEGRITY changed")
	}
	prefix := append([]byte(nil), padded[:20]...)
	binary.BigEndian.PutUint16(prefix[2:], 24)
	check := hmac.New(sha1.New, []byte("test-password"))
	check.Write(prefix)
	if !hmac.Equal(check.Sum(nil), padded[24:44]) {
		t.Fatal("MESSAGE-INTEGRITY no longer verifies")
	}
	at := fingerprint + 12
	if binary.BigEndian.Uint16(padded[at:]) != 0x8028 || binary.BigEndian.Uint32(padded[at+4:]) != crc32.ChecksumIEEE(padded[:at])^0x5354554e {
		t.Fatal("FINGERPRINT invalid")
	}
}

func TestQUICControlsIndependentOfSTUN(t *testing.T) {
	disabled := false
	o := option.DesyncOptions{Mode: "none", UDPMode: "auto", QUICDesync: &disabled, UDPRepeats: 2, UDPLen: 8, UDPFakePayload: base64.StdEncoding.EncodeToString([]byte("FAKE"))}
	s, err := newUDPState(context.Background(), o, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer s.stop()
	var sent [][]byte
	send := func(b []byte) (int, error) { sent = append(sent, append([]byte(nil), b...)); return len(b), nil }
	ttl := func(_ int, send func([]byte) (int, error), burst func(func([]byte) (int, error)) error) error {
		return burst(send)
	}
	packet := makeInitial(t, 1, []byte("test-id"), 0, 1, make([]byte, 40), 2)
	n, err := s.write(packet, "quic", nil, send, ttl)
	if err != nil || n != len(packet) {
		t.Fatal(n, err)
	}
	if len(sent) != 1 || !bytes.Equal(sent[0], packet) {
		t.Fatal("quic_desync=false transformed QUIC")
	}
	stun := make([]byte, 20)
	stun[1] = 1
	binary.BigEndian.PutUint32(stun[4:], 0x2112a442)
	sent = nil
	if _, err = s.write(stun, "stun", nil, send, ttl); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 3 || string(sent[0]) != "FAKE" || len(sent[2]) != 28 {
		t.Fatal("QUIC disable affected STUN")
	}
	enabled := true
	o.QUICDesync = &enabled
	o.QUICRepeats = 4
	o.UDPLen = 0
	s2, err := newUDPState(context.Background(), o, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer s2.stop()
	sent = nil
	if _, err = s2.write(packet, "quic", nil, send, ttl); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 5 {
		t.Fatalf("quic_repeats override emitted %d packets want5", len(sent))
	}
}

func TestUDPWriteDeadlinePreventsFakeBurst(t *testing.T) {
	s, err := newUDPState(context.Background(), option.DesyncOptions{Mode: "none", UDPMode: "stun", UDPRepeats: 2}, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer s.stop()
	if err = s.setDeadline(time.Now().Add(-time.Second), func(time.Time) error { return nil }); err != nil {
		t.Fatal(err)
	}
	calls := 0
	payload := make([]byte, 20)
	binary.BigEndian.PutUint32(payload[4:], 0x2112a442)
	_, err = s.write(payload, "dst", nil, func(b []byte) (int, error) { calls++; return len(b), nil }, func(_ int, send func([]byte) (int, error), burst func(func([]byte) (int, error)) error) error {
		return burst(send)
	})
	if !errors.Is(err, os.ErrDeadlineExceeded) || calls != 0 {
		t.Fatalf("expired write sent %d datagrams: %v", calls, err)
	}
}
