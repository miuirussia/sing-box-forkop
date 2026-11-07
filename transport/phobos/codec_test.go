package phobos

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestCodec(t *testing.T) {
	for _, limit := range []int{0, 4, 16, 148, 512, 2048} {
		for _, kind := range []byte{1, 2, 3, 4} {
			for _, size := range []int{4, 64, 148, 1023, 1024, 1408, 65000} {
				o := Options{Key: "test-key", MaxDummy: 1024, ObfuscateBytes: limit}
				packet := bytes.Repeat([]byte{0xab}, size)
				copy(packet, []byte{kind, 0, 0, 0})
				original := bytes.Clone(packet)
				encoded, err := o.encode(packet)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := o.decode(encoded)
				if err != nil || !bytes.Equal(decoded, original) {
					t.Fatalf("limit=%d kind=%d size=%d: %v", limit, kind, size, err)
				}
				if !bytes.Equal(packet, original) {
					t.Fatal("modified caller buffer")
				}
			}
		}
	}
}

func TestReferenceCodec(t *testing.T) {
	reference := os.Getenv("PHOBOS_REFERENCE")
	if reference == "" {
		t.Skip("set PHOBOS_REFERENCE to the compiled testdata/reference.c")
	}
	for _, limit := range []int{0, 4, 16, 148, 512} {
		for _, kind := range []byte{1, 2, 3, 4} {
			packet := bytes.Repeat([]byte{0x39}, 148)
			copy(packet, []byte{kind, 0, 0, 0})
			o := Options{Key: "compatibility-key", MaxDummy: 4, ObfuscateBytes: limit}
			run := func(mode string, b []byte) []byte {
				t.Helper()
				out, err := exec.Command(reference, mode, o.Key, strconv.Itoa(limit), hex.EncodeToString(b)).CombinedOutput()
				if err != nil {
					t.Fatalf("reference: %s: %v", out, err)
				}
				result, err := hex.DecodeString(strings.TrimSpace(string(out)))
				if err != nil {
					t.Fatal(err)
				}
				return result
			}
			encoded, err := o.encode(packet)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(run("decode", encoded), packet) {
				t.Fatal("C could not decode Go packet")
			}
			decoded, err := o.decode(run("encode", packet))
			if err != nil || !bytes.Equal(decoded, packet) {
				t.Fatalf("Go could not decode C packet: %v", err)
			}
		}
	}
}
func TestNormalize(t *testing.T) {
	zero := 0
	for _, mode := range []string{"STUN", "NONE", "AUTO", "MEDIA"} {
		o, err := Normalize(&option.PhobosObfuscationOptions{Key: "test", Masking: mode})
		if err != nil {
			t.Fatal(err)
		}
		if mode == "MEDIA" && o.ObfuscateBytes != 16 {
			t.Fatal("MEDIA default")
		}
		o, err = Normalize(&option.PhobosObfuscationOptions{Key: "test", Masking: mode, ObfuscateBytes: &zero, MaxDummy: &zero})
		if err != nil || o.ObfuscateBytes != 0 || o.MaxDummy != 0 {
			t.Fatal("explicit zero lost")
		}
	}
	for _, raw := range []*option.PhobosObfuscationOptions{nil, {}, {Key: "a\x00b"}, {Key: strings.Repeat("x", 256)}, {Key: "x", Masking: "TLS"}, {Key: "x", MediaClock: 1001}, {Key: "x", MediaPT: 128}} {
		if _, err := Normalize(raw); err == nil {
			t.Fatalf("accepted %+v", raw)
		}
	}
}
func FuzzDecode(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4}, 0)
	f.Add(stun(0x115, []byte{1, 2, 3, 4}), 16)
	f.Fuzz(func(t *testing.T, b []byte, limit int) {
		if limit < 0 {
			return
		}
		o := Options{Key: "test", ObfuscateBytes: limit}
		_, _ = o.decode(bytes.Clone(b))
		for _, mode := range []string{"STUN", "NONE", "MEDIA", "AUTO"} {
			bind := &Bind{options: Options{Key: "test", Masking: mode, ObfuscateBytes: limit}}
			if len(b) >= 2 && b[0] == 0 && b[1] == 1 {
				continue
			}
			_ = bind.unwrap(bytes.Clone(b), nil)
		}
	})
}

// Frozen packets produced by upstream's encode(), not by the Go codec.
func TestReferenceVectors(t *testing.T) {
	content, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Partial            int
		Plaintext, Encoded string
	}
	if err = json.Unmarshal(content, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors {
		encoded, err := hex.DecodeString(vector.Encoded)
		if err != nil {
			t.Fatal(err)
		}
		plaintext, err := hex.DecodeString(vector.Plaintext)
		if err != nil {
			t.Fatal(err)
		}
		o := Options{Key: "compatibility-key", ObfuscateBytes: vector.Partial}
		got, err := o.decode(encoded)
		if err != nil || !bytes.Equal(got, plaintext) {
			t.Fatalf("upstream vector partial=%d: %v", vector.Partial, err)
		}
		// Version 0 has only the XOR layer, with the original WireGuard header.
		legacy := bytes.Clone(plaintext)
		xor(legacy, o.Key, o.ObfuscateBytes)
		got, err = o.decode(legacy)
		if err != nil || !bytes.Equal(got, plaintext) {
			t.Fatalf("legacy decode: %v", err)
		}
	}
}
