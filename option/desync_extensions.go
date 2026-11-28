package option

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ValidateDesyncExtensions is shared by import/normalization and the engine so
// direct Go callers receive the same checks as JSON configurations.
func ValidateDesyncExtensions(o DesyncOptions) error {
	recordSpec := o.TLSRecPos
	if recordSpec == "" && (o.Mode == "tlsrec" || o.TLSRecFirst) {
		recordSpec = o.SplitPos
	}
	for _, p := range strings.Split(recordSpec, ",") {
		if n, err := strconv.Atoi(p); err == nil && n <= 5 {
			return fmt.Errorf("TLS record split %q is inside the first record header or at its payload boundary", p)
		}
	}
	for key, spec := range map[string]string{"tlsrec_pos": o.TLSRecPos, "quic_split_pos": o.QUICSplitPos} {
		if spec == "" {
			continue
		}
		if len(spec) > 1024 || strings.Count(spec, ",") >= 16 {
			return fmt.Errorf("%s supports at most 16 bounded markers", key)
		}
		for _, p := range strings.Split(spec, ",") {
			if !desyncPosition.MatchString(p) {
				return fmt.Errorf("invalid %s %q", key, p)
			}
		}
	}
	if o.TLSRecPos != "" && o.Mode != "tlsrec" && !o.TLSRecFirst {
		return fmt.Errorf("tlsrec_pos requires mode=tlsrec or tlsrec_first=true")
	}
	for key, spec := range map[string]string{"segment_order": o.SegmentOrder, "quic_order": o.QUICOrder} {
		if spec == "" || spec == "forward" || spec == "reverse" || spec == "sni_last" {
			continue
		}
		parts := strings.Split(spec, ",")
		if len(parts) > 17 {
			return fmt.Errorf("%s supports at most 17 segments", key)
		}
		seen := make(map[int]bool, len(parts))
		for _, p := range parts {
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > len(parts) || seen[n] {
				return fmt.Errorf("%s must be forward, reverse, sni_last, or a one-based permutation", key)
			}
			seen[n] = true
		}
	}
	if o.SegmentOrder != "" && (o.Mode == "none" || o.Mode == "" || o.Mode == "fake" || o.Mode == "oob" || o.Mode == "tlsrec") {
		return fmt.Errorf("segment_order requires a TCP segmentation mode")
	}
	fake := desyncContains([]string{"fake", "fake_split", "fake_disorder", "hostfakesplit", "oob", "disoob"}, o.Mode)
	if !desyncContains([]string{"", "before", "between", "before_between"}, o.FakePlacement) {
		return fmt.Errorf("fake_placement must be before, between, or before_between")
	}
	if o.FakeDelay < 0 || time.Duration(o.FakeDelay) > time.Second {
		return fmt.Errorf("fake_delay must be 0..1s")
	}
	if !desyncContains([]string{"", "original", "compact"}, o.FakeTLSTemplate) {
		return fmt.Errorf("fake_tls_template must be original or compact")
	}
	if o.FakeTLSSize < 0 || o.FakeTLSSize > 60000 {
		return fmt.Errorf("fake_tls_size must be 0..60000")
	}
	if !fake && (o.FakePlacement != "" || o.FakeDelay != 0 || o.FakeTLSRandom || o.FakeTLSSize != 0 || o.FakeTLSTemplate != "") {
		return fmt.Errorf("fake placement, delay and TLS transformations require a fake mode")
	}
	if (o.FakePlacement == "between" || o.FakePlacement == "before_between") && (o.Mode == "fake" || o.Mode == "oob") {
		return fmt.Errorf("interleaved fake placement requires a TCP segmentation mode")
	}
	if !desyncContains([]string{"", "legacy", "replace"}, o.HostFakeMode) || (o.HostFakeMode != "" && o.Mode != "hostfakesplit") {
		return fmt.Errorf("hostfake_mode requires hostfakesplit and must be legacy or replace")
	}
	if o.HostFakeMode == "replace" && (o.FakePayload != "" || o.FakeTLSRandom || o.FakeTLSSize != 0 || o.FakeTLSTemplate != "") {
		return fmt.Errorf("hostfake_mode=replace requires a length-preserving generated host decoy")
	}
	if o.HTTPMod != "" {
		seen := make(map[string]bool)
		for _, mod := range strings.Split(o.HTTPMod, ",") {
			if !desyncContains([]string{"hcsmix", "dcsmix", "rmspace"}, mod) || seen[mod] {
				return fmt.Errorf("http_mod requires unique hcsmix, dcsmix, rmspace tokens")
			}
			seen[mod] = true
		}
	}
	if o.QUICSplitPos != "" || o.QUICOrder != "" {
		if o.UDPMode != "quic" && o.UDPMode != "auto" {
			return fmt.Errorf("QUIC CRYPTO transformations require udp_mode=quic or auto")
		}
		if o.QUICDesync != nil && !*o.QUICDesync {
			return fmt.Errorf("QUIC CRYPTO transformations require quic_desync=true")
		}
		if o.QUICOrder != "" && o.QUICSplitPos == "" {
			return fmt.Errorf("quic_order requires quic_split_pos")
		}
	}
	return nil
}
