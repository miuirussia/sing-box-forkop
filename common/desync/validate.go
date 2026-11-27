package desync

import (
	"encoding/base64"
	"fmt"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
)

func rawMode(mode string) bool {
	switch mode {
	case "disorder", "fake", "fake_split", "oob", "fake_disorder", "multi_disorder", "disoob", "hostfakesplit":
		return true
	}
	return false
}
func fakeMode(mode string) bool {
	switch mode {
	case "fake", "fake_split", "fake_disorder", "hostfakesplit", "oob", "disoob":
		return true
	}
	return false
}

// Validate rejects settings which cannot have their specified wire effect.
// Call option.NormalizeDesyncOptions before this function.
func Validate(o option.DesyncOptions) error {
	switch o.Mode {
	case "", "none", "split", "disorder", "tlsrec", "fake", "fake_split", "oob", "multi_split", "fake_disorder", "multi_disorder", "disoob", "hostfakesplit":
	default:
		return fmt.Errorf("desync: unknown mode %q", o.Mode)
	}
	if err := validatePreSYN(o); err != nil {
		return err
	}

	if !o.UDPKeepSocket && o.IsExplicit("udp_keep_socket") && runtime.GOOS != "linux" {
		return fmt.Errorf("desync: udp_keep_socket=false requires Linux raw UDP with CAP_NET_RAW")
	}

	if !fakeMode(o.Mode) && o.Repeats > 1 {
		return fmt.Errorf("desync: repeats>1 requires a fake mode")
	}
	if (o.Mode == "none" || o.Mode == "") && o.Delay > 0 {
		return fmt.Errorf("desync: delay requires an enabled TCP mode")
	}
	if o.Repeats < 0 || o.Repeats > 64 || o.UDPRepeats < 0 || o.UDPRepeats > 64 {
		return fmt.Errorf("desync: repeats must be between 0 and 64")
	}
	if o.TTL < 0 || o.TTL > 255 || o.UDPTTL < 0 || o.UDPTTL > 255 {
		return fmt.Errorf("desync: TTL must be between 0 and 255")
	}
	if o.WSize < 0 || o.WSize > 65535 {
		return fmt.Errorf("desync: wsize must be between 0 and 65535")
	}
	if o.SeqOvl < 0 || o.SeqOvl > 4096 {
		return fmt.Errorf("desync: seqovl must be between 0 and 4096")
	}
	if o.IPFrag != 0 && (o.IPFrag < 8 || o.IPFrag > 65512 || o.IPFrag%8 != 0) {
		return fmt.Errorf("desync: ipfrag must be a multiple of 8 between 8 and 65512")
	}
	if o.Delay < 0 || int64(o.Delay) > int64(10e9) {
		return fmt.Errorf("desync: delay must be between 0 and 10s")
	}
	if (rawMode(o.Mode) || o.IPFrag != 0 || o.SeqOvl != 0 || o.WSize != 0 || o.AutoTTL) && runtime.GOOS != "linux" {
		return fmt.Errorf("desync: mode %s and raw TCP options require Linux with CAP_NET_RAW and CAP_NET_ADMIN", o.Mode)
	}
	if o.Mode == "" || o.Mode == "none" {
		if o.IPFrag != 0 || o.SeqOvl != 0 || o.WSize != 0 || o.TLSRecFirst {
			return fmt.Errorf("desync: TCP transformation options require an enabled TCP mode")
		}
	}
	if !fakeMode(o.Mode) && (o.FakeSNI != "" || o.FakeHost != "" || o.FakePayload != "" || len(o.FakeSNIPool) > 0 || o.Fooling != "" || (o.TTL != 0 && o.SynData == "") || o.AutoTTL) {
		return fmt.Errorf("desync: fake payload, fooling and TTL options require a fake mode")
	}
	if len(o.FakeSNIPool) > 64 {
		return fmt.Errorf("desync: fake_sni_pool supports at most64 names")
	}
	for _, name := range o.FakeSNIPool {
		if name == "" {
			return fmt.Errorf("desync: fake_sni_pool contains empty hostname")
		}
	}
	for _, s := range append(append([]string(nil), o.FakeSNIPool...), o.FakeSNI, o.FakeHost) {
		if len(s) > 253 || strings.ContainsAny(s, "\x00\r\n") {
			return fmt.Errorf("desync: invalid fake hostname")
		}
	}
	for _, payload := range []struct {
		name, value string
		limit       int
	}{{"fake_payload", o.FakePayload, 60000}, {"udp_fake_payload", o.UDPFakePayload, 65507}} {
		if payload.value == "" {
			continue
		}
		if len(payload.value) > base64.StdEncoding.EncodedLen(payload.limit) {
			return fmt.Errorf("desync: %s exceeds %d bytes", payload.name, payload.limit)
		}
		decoded, err := base64.StdEncoding.DecodeString(payload.value)
		if err != nil {
			return fmt.Errorf("desync: invalid base64 %s: %w", payload.name, err)
		}
		if len(decoded) == 0 || len(decoded) > payload.limit {
			return fmt.Errorf("desync: %s must contain 1..%d bytes", payload.name, payload.limit)
		}
	}

	if !slices.Contains(option.DesyncFoolingMethods, o.Fooling) {
		return fmt.Errorf("desync: unsupported fooling %q", o.Fooling)
	}
	if len(o.SplitPos) > 1024 || strings.Count(o.SplitPos, ",") >= 16 {
		return fmt.Errorf("desync: split_pos supports at most16 bounded markers")
	}
	if o.SplitPos != "" {
		for _, s := range strings.Split(o.SplitPos, ",") {
			s = strings.TrimSpace(s)
			if n, e := strconv.Atoi(s); e == nil {
				if n <= 0 {
					return fmt.Errorf("desync: numeric split positions must be positive")
				}
				continue
			}
			base := s
			for i := 1; i < len(s); i++ {
				if s[i] == '+' || s[i] == '-' {
					base = s[:i]
					if _, e := strconv.Atoi(s[i:]); e != nil {
						return fmt.Errorf("desync: invalid split offset %q", s)
					}
					break
				}
			}
			switch base {
			case "sni", "host", "midsld", "endhost", "sniext", "extlen":
			default:
				return fmt.Errorf("desync: invalid split marker %q", s)
			}
		}
	}
	switch o.UDPMode {
	case "", "none", "quic", "stun", "auto":
	default:
		return fmt.Errorf("desync: unsupported udp_mode %q", o.UDPMode)
	}
	if o.UDPMode == "" || o.UDPMode == "none" {
		if o.UDPFakePayload != "" || o.UDPTTL != 0 || o.UDPRepeats != 0 || o.UDPOutRange != "" || o.UDPLen != 0 {
			return fmt.Errorf("desync: UDP options require udp_mode")
		}
	}
	if o.QUICRepeats < 0 || o.QUICRepeats > 16 {
		return fmt.Errorf("desync: quic_repeats must be 0..16")
	}
	if (o.QUICDesync != nil || o.QUICRepeats != 0) && o.UDPMode != "quic" && o.UDPMode != "auto" {
		return fmt.Errorf("desync: QUIC options require udp_mode quic or auto")
	}
	if o.QUICDesync != nil && !*o.QUICDesync {
		if o.QUICRepeats > 0 {
			return fmt.Errorf("desync: quic_repeats conflicts with quic_desync=false")
		}
		if o.UDPMode == "quic" && o.UDPLen > 0 {
			return fmt.Errorf("desync: udplen conflicts with quic_desync=false in quic-only mode")
		}
	}
	if o.UDPLen < 0 || o.UDPLen > 64000 {
		return fmt.Errorf("desync: udplen must be 0..64000")
	}
	if o.UDPLen != 0 && o.UDPMode == "stun" && (o.UDPLen < 4 || o.UDPLen%4 != 0) {
		return fmt.Errorf("desync: STUN udplen must be a positive multiple of4")
	}

	_, _, err := packetRange(o.UDPOutRange)
	return err
}
func packetRange(spec string) (uint64, uint64, error) {
	if spec == "" {
		return 1, 1, nil
	}
	a, b, ok := strings.Cut(spec, ":")
	if !ok {
		return 0, 0, fmt.Errorf("desync: udp_out_range must be start:end inclusive")
	}
	start, e1 := strconv.ParseUint(a, 10, 64)
	end, e2 := strconv.ParseUint(b, 10, 64)
	if e1 != nil || e2 != nil || start < 1 || end < start || end > 1000000 {
		return 0, 0, fmt.Errorf("desync: invalid udp_out_range %q", spec)
	}
	return start, end, nil
}
