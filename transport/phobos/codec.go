// Package phobos implements the WireGuard transport of Ground-Zerro/Phobos.
// Wire format reference: Phobos commit 22aedefda053062dc58c036072d2da6e216d5a34.
package phobos

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"strings"

	"github.com/sagernet/sing-box/option"
)

// Options is a validated, normalized configuration; it is also part of the device identity.
type Options struct {
	Key            string
	Masking        string
	MaxDummy       int
	ObfuscateBytes int
	MediaPT        uint8
	MediaSSRC      uint32
	MediaClock     int
}

func Normalize(raw *option.PhobosObfuscationOptions) (*Options, error) {
	if raw == nil {
		return nil, fmt.Errorf("missing phobos obfuscation")
	}
	if len(raw.Key) < 1 || len(raw.Key) > 255 || strings.ContainsRune(raw.Key, 0) {
		return nil, fmt.Errorf("phobos key must contain 1–255 bytes without NUL")
	}
	o := &Options{Key: raw.Key, Masking: strings.ToUpper(raw.Masking), MaxDummy: 4, MediaPT: raw.MediaPT, MediaSSRC: raw.MediaSSRC, MediaClock: raw.MediaClock}
	if o.Masking == "" {
		o.Masking = "STUN"
	}
	switch o.Masking {
	case "STUN", "NONE", "AUTO", "MEDIA":
	default:
		return nil, fmt.Errorf("unsupported phobos masking: %s", o.Masking)
	}
	if o.Masking == "MEDIA" {
		o.ObfuscateBytes = 16
	}
	if raw.ObfuscateBytes != nil {
		o.ObfuscateBytes = *raw.ObfuscateBytes
	}
	if raw.MaxDummy != nil {
		o.MaxDummy = *raw.MaxDummy
	}
	if o.MaxDummy < 0 || o.MaxDummy > 1024 || o.ObfuscateBytes < 0 || int64(o.ObfuscateBytes) > 2147483647 || o.MediaPT > 127 || o.MediaClock < 0 || o.MediaClock > 1000 {
		return nil, fmt.Errorf("invalid phobos obfuscation parameters")
	}
	return o, nil
}

func xor(b []byte, key string, limit int) {
	n := len(b)
	if limit > 0 && limit < n {
		n = limit
	}
	var crc byte
	base := byte(n + len(key))
	for i := 0; i < n; i++ {
		crc ^= key[i%len(key)] + base
		for j := 0; j < 8; j++ {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0x8c
			} else {
				crc >>= 1
			}
		}
		b[i] ^= crc
	}
}

func (o *Options) encode(packet []byte) ([]byte, error) {
	if !validWG(packet) {
		return nil, fmt.Errorf("invalid WireGuard packet")
	}
	n := len(packet)
	dummy := 0
	partial := o.ObfuscateBytes > 0 && o.ObfuscateBytes < n
	if !partial && n < 1024 {
		bound := 1024 - n
		if o.ObfuscateBytes > 0 {
			bound = min(bound, o.ObfuscateBytes-n+1)
		}
		if packet[0] <= 2 {
			bound = min(bound, 512)
		} else {
			bound = min(bound, o.MaxDummy)
		}
		if bound > 0 {
			dummy = rand.IntN(bound)
		}
	}
	b := make([]byte, n+dummy)
	copy(b, packet)
	r := byte(1 + rand.IntN(255))
	b[0] ^= r
	b[1] = r
	binary.LittleEndian.PutUint16(b[2:4], uint16(dummy))
	for i := n; i < len(b); i++ {
		b[i] = byte(rand.Uint32())
	}
	xor(b, o.Key, o.ObfuscateBytes)
	return b, nil
}
func (o *Options) decode(b []byte) ([]byte, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("short phobos packet")
	}
	xor(b, o.Key, o.ObfuscateBytes)
	if !validWG(b) {
		dummy := int(binary.LittleEndian.Uint16(b[2:4]))
		if dummy > len(b)-4 {
			return nil, fmt.Errorf("invalid phobos padding")
		}
		b[0] ^= b[1]
		clear(b[1:4])
		b = b[:len(b)-dummy]
	}
	if !validWG(b) {
		return nil, fmt.Errorf("invalid decoded WireGuard packet")
	}
	return b, nil
}
func validWG(b []byte) bool {
	return len(b) >= 4 && b[0] >= 1 && b[0] <= 4 && b[1] == 0 && b[2] == 0 && b[3] == 0
}
