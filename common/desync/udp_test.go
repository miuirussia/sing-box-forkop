package desync

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"strings"
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

func TestUDPQUICCryptoSplitPath(t *testing.T) {
	hello := cryptoTestHello(t)
	for _, mode := range []string{"quic", "auto"} {
		for _, extra := range []int{0, 16} {
			t.Run(fmt.Sprintf("%s/udplen%d", mode, extra), func(t *testing.T) {
				o := option.DesyncOptions{
					Mode: "none", UDPMode: mode, QUICSplitPos: "host,endhost", QUICOrder: "reverse",
					UDPLen: extra, UDPRepeats: 2, QUICRepeats: 3, UDPOutRange: "2:2",
					UDPFakePayload: base64.StdEncoding.EncodeToString([]byte("FAKE")),
				}
				s, err := newUDPState(context.Background(), o, func() error { return nil })
				if err != nil {
					t.Fatal(err)
				}
				defer s.stop()
				var sent [][]byte
				send := func(b []byte) (int, error) {
					sent = append(sent, append([]byte(nil), b...))
					return len(b), nil
				}
				ttl := func(_ int, send func([]byte) (int, error), burst func(func([]byte) (int, error)) error) error {
					return burst(send)
				}
				for pn := uint64(0); pn < 3; pn++ {
					sent = nil
					original := paddedTestInitial(t, 1, pn, cryptoFrame(0, hello), 2400)
					n, err := s.write(original, "peer", nil, send, ttl)
					if err != nil || n != len(original) {
						t.Fatalf("write n=%d: %v", n, err)
					}
					want := 1
					if pn == 1 {
						want = 4
					}
					if len(sent) != want {
						t.Fatalf("sent %d datagrams want %d", len(sent), want)
					}
					for _, fake := range sent[:len(sent)-1] {
						if string(fake) != "FAKE" {
							t.Fatal("existing fake payload changed")
						}
					}
					real := sent[len(sent)-1]
					if len(real) != len(original)+extra {
						t.Fatal("unexpected transformed datagram length")
					}
					frames, _ := decodedCrypto(t, real, s.quic[initialConnectionKey{destination: "peer"}], pn)
					crypto := assertCryptoBytes(t, frames, hello)
					if len(crypto) != 3 || crypto[0].offset <= crypto[1].offset || crypto[1].offset <= crypto[2].offset {
						t.Fatal("UDP path did not reverse split CRYPTO frames")
					}
				}
			})
		}
	}
}

func TestUDPQUICCryptoRejectsBeforeFakeSends(t *testing.T) {
	for _, tc := range []struct {
		name, order string
		packet      []byte
	}{
		{"malformed frames", "reverse", makeInitial(t, 1, []byte("bad-frame"), 0, 1, []byte{1, 1, 1, 1, 6, 0, 63, 1}, 2)},
		{"wrong permutation", "3,2,1", paddedTestInitial(t, 1, 0, cryptoFrame(0, []byte("0123456789")), 1200)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := newUDPState(context.Background(), option.DesyncOptions{
				Mode: "none", UDPMode: "quic", QUICSplitPos: "2", QUICOrder: tc.order, UDPRepeats: 3,
			}, func() error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer s.stop()
			calls := 0
			_, err = s.write(tc.packet, "peer", nil, func(b []byte) (int, error) {
				calls++
				return len(b), nil
			}, func(_ int, send func([]byte) (int, error), burst func(func([]byte) (int, error)) error) error {
				return burst(send)
			})
			if err == nil || calls != 0 || s.quic[initialConnectionKey{destination: "peer"}].seen {
				t.Fatalf("invalid Initial sent %d datagrams and returned %v", calls, err)
			}
		})
	}
}

func TestUDPQUICCryptoDefaultFakeAndFailedWriteState(t *testing.T) {
	s, err := newUDPState(context.Background(), option.DesyncOptions{
		Mode: "none", UDPMode: "quic", QUICSplitPos: "2", QUICOrder: "reverse", UDPRepeats: 1, UDPOutRange: "1:2",
	}, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer s.stop()
	original := paddedTestInitial(t, 1, 0, cryptoFrame(0, []byte("0123456789")), 1200)
	ttl := func(_ int, send func([]byte) (int, error), burst func(func([]byte) (int, error)) error) error {
		return burst(send)
	}
	calls := 0
	_, err = s.write(original, "peer", nil, func(b []byte) (int, error) {
		calls++
		if calls == 1 {
			if !bytes.Equal(b, fakeQUICInitial(original)) {
				t.Fatal("default fake no longer derives from original Initial")
			}
			return len(b), nil
		}
		return 0, io.ErrClosedPipe
	}, ttl)
	if !errors.Is(err, io.ErrClosedPipe) || calls != 2 || s.quic[initialConnectionKey{destination: "peer"}].seen {
		t.Fatalf("failed write committed state: calls=%d err=%v", calls, err)
	}
	calls = 0
	_, err = s.write(original, "peer", nil, func(b []byte) (int, error) {
		calls++
		return len(b), nil
	}, ttl)
	if err != nil || calls != 2 || !s.quic[initialConnectionKey{destination: "peer"}].seen {
		t.Fatalf("successful write did not commit state: calls=%d err=%v", calls, err)
	}
}

func TestUDPQUICInterleavedConnections(t *testing.T) {
	for _, version := range []uint32{1, 0x6b3343cf} {
		for _, tc := range []struct {
			name, split string
			extra       int
		}{{"crypto", "2", 0}, {"padding", "", 8}, {"combined", "2", 8}} {
			t.Run(fmt.Sprintf("%x/%s", version, tc.name), func(t *testing.T) {
				s, err := newUDPState(context.Background(), option.DesyncOptions{
					Mode: "none", UDPMode: "quic", QUICSplitPos: tc.split, UDPLen: tc.extra,
					UDPOutRange: "99:99",
				}, func() error { return nil })
				if err != nil {
					t.Fatal(err)
				}
				defer s.stop()
				data := []byte("0123456789")
				plain := append(cryptoFrame(0, data), make([]byte, 1200)...)
				clientA, clientB := []byte("client-A-id"), []byte("client-B-id")
				originalA, originalB := []byte("original-A"), []byte("original-B")
				serverA, serverB := []byte("server-A-id"), []byte("server-B-id")
				retryA := []byte("retry-A-id")
				for _, step := range []struct {
					name              string
					key, dcid, client []byte
					pn                uint64
				}{
					{"A first", originalA, originalA, clientA, 254},
					{"B first", originalB, originalB, clientB, 10},
					{"A server CID", originalA, serverA, clientA, 255},
					{"B server CID", originalB, serverB, clientB, 11},
					{"A PN wrap", originalA, serverA, clientA, 256},
					{"B continues", originalB, serverB, clientB, 12},
					{"A Retry", retryA, retryA, clientA, 257},
					{"B after A Retry", originalB, serverB, clientB, 13},
					{"A server CID after Retry", retryA, serverA, clientA, 258},
				} {
					width := 1
					if bytes.Equal(step.dcid, step.key) && !bytes.Equal(step.key, retryA) {
						width = 2
					}
					packet := connectionTestInitial(t, version, step.key, step.dcid, step.client, step.pn, width, plain)
					calls := 0
					n, err := s.write(packet, "same-peer", nil, func(wire []byte) (int, error) {
						calls++
						frames, h := decodedCrypto(t, wire, initialState{dcid: string(step.key), largest: step.pn, seen: true}, step.pn)
						assertCryptoBytes(t, frames, data)
						if !bytes.Equal(h.dcid, step.dcid) || !bytes.Equal(h.scid, step.client) || len(wire) != len(packet)+tc.extra {
							t.Fatalf("%s: connection IDs or datagram size changed", step.name)
						}
						return len(wire), nil
					}, nil)
					if err != nil || n != len(packet) || calls != 1 {
						t.Fatalf("%s: write=%d sends=%d error=%v", step.name, n, calls, err)
					}
				}
				if len(s.quic) != 2 || s.quic[initialConnectionKey{"same-peer", string(clientA)}].largest != 258 || s.quic[initialConnectionKey{"same-peer", string(clientB)}].largest != 13 {
					t.Fatalf("connections lost independent packet number history: %+v", s.quic)
				}
			})
		}
	}
}

func TestUDPQUICConnectionCacheLimit(t *testing.T) {
	s, err := newUDPState(context.Background(), option.DesyncOptions{
		Mode: "none", UDPMode: "quic", QUICSplitPos: "2", UDPRepeats: 1,
		UDPOutRange: "1:2048", UDPFakePayload: base64.StdEncoding.EncodeToString([]byte("FAKE")),
	}, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer s.stop()
	plain := append(cryptoFrame(0, []byte("0123456789")), make([]byte, 1200)...)
	dcid := []byte("original-id")
	ttl := func(_ int, send func([]byte) (int, error), burst func(func([]byte) (int, error)) error) error {
		return burst(send)
	}
	calls := 0
	send := func(b []byte) (int, error) { calls++; return len(b), nil }
	for i := 0; i < maxQUICConnections; i++ {
		scid := []byte(fmt.Sprintf("client-%04d", i))
		packet := connectionTestInitial(t, 1, dcid, dcid, scid, 0, 2, plain)
		if _, err = s.write(packet, "peer", nil, send, ttl); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.quic) != maxQUICConnections {
		t.Fatalf("cache has %d entries", len(s.quic))
	}
	for _, destination := range []string{"peer", "other-peer"} {
		t.Run(destination, func(t *testing.T) {
			// A distinct SCID and the same SCID on a different destination both
			// need new entries. Reject before even the configured fake burst.
			scid := []byte("another-client")
			if destination == "other-peer" {
				scid = []byte("client-0000")
			}
			packet := connectionTestInitial(t, 1, dcid, dcid, scid, 0, 2, plain)
			before := calls
			n, err := s.write(packet, destination, nil, send, ttl)
			if err == nil || !strings.Contains(err.Error(), "QUIC connection limit") || n != 0 || calls != before || len(s.quic) != maxQUICConnections {
				t.Fatalf("limit changed cache or sent traffic: n=%d sends=%d size=%d err=%v", n, calls-before, len(s.quic), err)
			}
		})
	}
	// Admission failure must leave existing connections usable at capacity,
	// including the original keys after the server chooses a new wire DCID.
	packet := connectionTestInitial(t, 1, dcid, []byte("server-id"), []byte("client-0000"), 1, 2, plain)
	if _, err = s.write(packet, "peer", nil, send, ttl); err != nil || len(s.quic) != maxQUICConnections {
		t.Fatalf("existing connection failed at capacity: %v", err)
	}
}

func TestUDPQUICConnectionFailedSendDoesNotCommit(t *testing.T) {
	for _, failure := range []string{"fake error", "fake short", "real error", "real short"} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/existing=%v", failure, existing), func(t *testing.T) {
				s, err := newUDPState(context.Background(), option.DesyncOptions{
					Mode: "none", UDPMode: "quic", QUICSplitPos: "2", UDPRepeats: 1,
					UDPOutRange: "1:3", UDPFakePayload: base64.StdEncoding.EncodeToString([]byte("FAKE")),
				}, func() error { return nil })
				if err != nil {
					t.Fatal(err)
				}
				defer s.stop()
				plain := append(cryptoFrame(0, []byte("0123456789")), make([]byte, 1200)...)
				dcid, retry, scid := []byte("original-id"), []byte("retry-id"), []byte("client-id")
				ttl := func(_ int, send func([]byte) (int, error), burst func(func([]byte) (int, error)) error) error {
					return burst(send)
				}
				success := func(b []byte) (int, error) { return len(b), nil }
				key := initialConnectionKey{"peer", string(scid)}
				pn := uint64(0)
				if existing {
					packet := connectionTestInitial(t, 1, dcid, dcid, scid, 255, 2, plain)
					if _, err = s.write(packet, "peer", nil, success, ttl); err != nil {
						t.Fatal(err)
					}
					pn = 256 // Retry must not commit new keys or a reconstructed PN on failure.
				}
				before, size := s.quic[key], len(s.quic)
				packet := connectionTestInitial(t, 1, retry, retry, scid, pn, 1, plain)
				calls := 0
				n, err := s.write(packet, "peer", nil, func(b []byte) (int, error) {
					calls++
					fail := strings.HasPrefix(failure, "fake") && calls == 1 || strings.HasPrefix(failure, "real") && calls == 2
					if fail {
						if strings.HasSuffix(failure, "short") {
							return len(b) - 1, nil
						}
						return len(b) / 2, io.ErrClosedPipe
					}
					return len(b), nil
				}, ttl)
				wantCalls := 1
				if strings.HasPrefix(failure, "real") {
					wantCalls = 2
				}
				if err == nil || n != 0 || calls != wantCalls || len(s.quic) != size || s.quic[key] != before {
					t.Fatalf("failed send committed cache: n=%d calls=%d state=%+v err=%v", n, calls, s.quic[key], err)
				}
				if _, err = s.write(packet, "peer", nil, success, ttl); err != nil {
					t.Fatal(err)
				}
				if state := s.quic[key]; !state.seen || state.dcid != string(retry) || state.largest != pn {
					t.Fatalf("successful send did not commit: %+v", state)
				}
			})
		}
	}
}
