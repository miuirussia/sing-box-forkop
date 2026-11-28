package option

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing/common/json/badoption"
)

// DesyncOptions is the flat, versioned Forkop strategy format. JSON presence is
// retained so explicit false and zero values override a preset.
type DesyncOptions struct {
	DialerOptions
	Preset          string                 `json:"preset,omitempty"`
	Mode            string                 `json:"mode,omitempty"`
	SplitPos        string                 `json:"split_pos,omitempty"`
	TLSRecPos       string                 `json:"tlsrec_pos,omitempty"`
	SegmentOrder    string                 `json:"segment_order,omitempty"`
	FakePlacement   string                 `json:"fake_placement,omitempty"`
	FakeDelay       badoption.Duration     `json:"fake_delay,omitempty"`
	FakeTLSRandom   bool                   `json:"fake_tls_random,omitempty"`
	FakeTLSSize     int                    `json:"fake_tls_size,omitempty"`
	FakeTLSTemplate string                 `json:"fake_tls_template,omitempty"`
	HTTPMod         string                 `json:"http_mod,omitempty"`
	HostFakeMode    string                 `json:"hostfake_mode,omitempty"`
	FakeSNI         string                 `json:"fake_sni,omitempty"`
	FakeHost        string                 `json:"fake_host,omitempty"`
	FakePayload     string                 `json:"fake_payload,omitempty"`
	FakeSNIPool     []string               `json:"fake_sni_pool,omitempty"`
	Repeats         int                    `json:"repeats,omitempty"`
	Delay           badoption.Duration     `json:"delay,omitempty"`
	TTL             int                    `json:"ttl,omitempty"`
	Fooling         string                 `json:"fooling,omitempty"`
	TLSRecFirst     bool                   `json:"tlsrec_first,omitempty"`
	SeqOvl          int                    `json:"seqovl,omitempty"`
	AutoTTL         bool                   `json:"autottl,omitempty"`
	IPFrag          int                    `json:"ipfrag,omitempty"`
	SynData         string                 `json:"syndata,omitempty"`
	WSize           int                    `json:"wsize,omitempty"`
	WScale          int                    `json:"wscale,omitempty"`
	UDPMode         string                 `json:"udp_mode,omitempty"`
	UDPFakePayload  string                 `json:"udp_fake_payload,omitempty"`
	UDPTTL          int                    `json:"udp_ttl,omitempty"`
	UDPRepeats      int                    `json:"udp_repeats,omitempty"`
	UDPOutRange     string                 `json:"udp_out_range,omitempty"`
	UDPKeepSocket   bool                   `json:"udp_keep_socket,omitempty"`
	UDPLen          int                    `json:"udplen,omitempty"`
	QUICDesync      *bool                  `json:"quic_desync,omitempty"`
	QUICRepeats     int                    `json:"quic_repeats,omitempty"`
	QUICSplitPos    string                 `json:"quic_split_pos,omitempty"`
	QUICOrder       string                 `json:"quic_order,omitempty"`
	AutoTune        *bool                  `json:"auto_tune,omitempty"`
	Adaptive        *DesyncAdaptiveOptions `json:"adaptive,omitempty"`
	Strategy        string                 `json:"strategy,omitempty"`
	WScaleExplicit  bool                   `json:"-"`
	present         map[string]json.RawMessage
}

type DesyncAdaptiveOptions struct {
	MaxAttempts   int                `json:"max_attempts,omitempty"`
	MaxConcurrent int                `json:"max_concurrent,omitempty"`
	MaxEntries    int                `json:"max_entries,omitempty"`
	TTL           badoption.Duration `json:"ttl,omitempty"`
	Timeout       badoption.Duration `json:"timeout,omitempty"`
	MaxBuffer     int                `json:"max_buffer,omitempty"`
	NetworkID     string             `json:"network_id,omitempty"`
	present       map[string]json.RawMessage
}

type desyncAdaptiveJSON DesyncAdaptiveOptions

func (a *DesyncAdaptiveOptions) UnmarshalJSON(data []byte) error {
	var value desyncAdaptiveJSON
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&value); err != nil {
		return err
	}
	*a = DesyncAdaptiveOptions(value)
	if err := json.Unmarshal(data, &a.present); err != nil {
		return err
	}
	for key, value := range a.present {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("adaptive %s cannot be null", key)
		}
	}
	return nil
}

type desyncOptionsJSON DesyncOptions

func (o *DesyncOptions) UnmarshalJSON(data []byte) error {
	var value desyncOptionsJSON
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&value); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("unexpected trailing JSON")
	}
	*o = DesyncOptions(value)
	if err := json.Unmarshal(data, &o.present); err != nil {
		return err
	}
	if o.present == nil {
		return fmt.Errorf("desync options must be a JSON object")
	}
	for key, value := range o.present {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("desync %s cannot be null", key)
		}
	}
	return nil
}

// MarshalJSON preserves explicit zero values through import/export cycles.
func (o DesyncOptions) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(desyncOptionsJSON(o))
	if err != nil {
		return nil, err
	}
	var values map[string]json.RawMessage
	_ = json.Unmarshal(data, &values)
	v, t := reflect.ValueOf(o), reflect.TypeOf(o)
	for i := 1; i < t.NumField()-1; i++ {
		key := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
		if _, ok := o.present[key]; ok {
			values[key], err = json.Marshal(v.Field(i).Interface())
			if err != nil {
				return nil, err
			}
		}
	}
	if o.WScaleExplicit {
		values["wscale"], err = json.Marshal(o.WScale)
		if err != nil {
			return nil, err
		}
	}
	return json.Marshal(values)
}

var desyncPosition = regexp.MustCompile(`^(?:[1-9][0-9]*|(?:sni|host|midsld|sniext|endhost|extlen)(?:[+-][0-9]+)?)$`)
var DesyncModes = []string{"none", "split", "disorder", "tlsrec", "fake", "fake_split", "oob", "multi_split", "fake_disorder", "multi_disorder", "disoob", "hostfakesplit"}
var DesyncPresets = []string{"auto", "custom", "split", "disorder", "tlsrec", "fake", "fake_split", "oob", "GT1", "GT2", "GT3", "GT4"}

// These exact tokens form the strategy contract. badtimestamp aliases ts on the
// wire; both spellings are preserved by import/export. Other combinations are
// rejected rather than accepting arbitrary strings of low-level packet flags.
var DesyncFoolingMethods = []string{"", "none", "badseq", "badack", "badsum", "md5", "md5_badack", "badseq_badack_badsum", "datanoack", "hopbyhop", "destopt", "ipfrag", "ts", "badtimestamp"}

func desyncContains(values []string, v string) bool {
	for _, x := range values {
		if x == v {
			return true
		}
	}
	return false
}

// NormalizeDesyncOptions applies defaults < preset < imported strategy < explicit JSON.
func NormalizeDesyncOptions(o DesyncOptions) (DesyncOptions, error) {
	var imported DesyncOptions
	if o.Strategy != "" {
		var err error
		imported, err = ParseDesyncStrategy(o.Strategy)
		if err != nil {
			return o, err
		}
	}
	preset := o.Preset
	if _, explicit := o.present["preset"]; !explicit && preset == "" {
		preset = imported.Preset
	}
	base := DesyncOptions{Mode: "split", SplitPos: "midsld", UDPMode: "none"}
	switch preset {
	case "", "custom":
	case "auto":
		base.Mode = "split"
		v := true
		base.AutoTune = &v
	case "split", "disorder", "tlsrec", "fake", "fake_split", "oob":
		base.Mode = preset
	case "GT1", "GT2", "GT3", "GT4":
		base.Mode = "none"
		base.UDPMode = "auto"
		base.UDPRepeats = int(preset[2] - '0')
		base.UDPOutRange = "1:" + strconv.Itoa(base.UDPRepeats)
	default:
		return o, fmt.Errorf("unknown desync preset %q", preset)
	}
	merge := func(src DesyncOptions) {
		sv, dv, t := reflect.ValueOf(src), reflect.ValueOf(&base).Elem(), reflect.TypeOf(src)
		for i := 1; i < t.NumField()-1; i++ {
			key := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
			_, explicit := src.present[key]
			if explicit || !sv.Field(i).IsZero() {
				dv.Field(i).Set(sv.Field(i))
			}
		}
	}
	presence := make(map[string]json.RawMessage)
	if o.Strategy != "" {
		merge(imported)
		for k, v := range imported.present {
			presence[k] = v
		}
	}
	merge(o)
	for k, v := range o.present {
		presence[k] = v
	}
	base.DialerOptions = o.DialerOptions
	base.Strategy = ""
	fake := desyncContains([]string{"fake", "fake_split", "fake_disorder", "hostfakesplit", "oob", "disoob"}, base.Mode)
	if _, explicit := presence["split_pos"]; explicit && base.SplitPos != "" && (base.Mode == "none" || ((base.Mode == "fake" || base.Mode == "oob") && base.IPFrag == 0 && base.SeqOvl == 0 && base.WSize == 0 && !base.TLSRecFirst)) {
		return base, fmt.Errorf("split_pos has no effect in mode %s without real-segment transformation", base.Mode)
	}
	if base.Mode == "none" || ((base.Mode == "fake" || base.Mode == "oob") && !base.TLSRecFirst) {
		if _, explicit := presence["split_pos"]; !explicit {
			base.SplitPos = ""
		}
	}
	if fake {
		if base.FakeDelay == 0 {
			if _, explicit := presence["fake_delay"]; !explicit {
				base.FakeDelay = base.Delay
			}
		}
		if base.Repeats == 0 {
			if _, explicit := presence["repeats"]; !explicit {
				base.Repeats = 1
			}
		}
		if base.TTL == 0 {
			if _, explicit := presence["ttl"]; !explicit {
				base.TTL = 3
			}
		}
		if base.Fooling == "" {
			if _, explicit := presence["fooling"]; !explicit {
				base.Fooling = "badseq"
			}
		}
	}
	if base.UDPMode != "none" {
		if base.UDPTTL == 0 {
			if _, explicit := presence["udp_ttl"]; !explicit {
				base.UDPTTL = 3
			}
		}
		if base.UDPRepeats == 0 {
			if _, explicit := presence["udp_repeats"]; !explicit {
				base.UDPRepeats = 1
			}
		}
		if base.UDPOutRange == "" {
			base.UDPOutRange = "1:1"
		}
		if _, explicit := presence["udp_keep_socket"]; !explicit {
			base.UDPKeepSocket = true
		}
	}
	base.present = presence
	if _, explicit := presence["wscale"]; explicit {
		base.WScaleExplicit = true
	}
	if !desyncContains(DesyncModes, base.Mode) {
		return base, fmt.Errorf("unknown desync mode %q", base.Mode)
	}
	positions := strings.Split(base.SplitPos, ",")
	if len(positions) > 16 {
		return base, fmt.Errorf("split_pos: at most 16 positions")
	}
	for _, p := range positions {
		if !desyncPosition.MatchString(p) && !(p == "" && (base.Mode == "none" || ((base.Mode == "fake" || base.Mode == "oob") && !base.TLSRecFirst))) {
			return base, fmt.Errorf("invalid split_pos %q", p)
		}
	}
	if base.Repeats < 0 || base.Repeats > 16 || (fake && base.Repeats == 0) || base.UDPRepeats < 0 || base.UDPRepeats > 16 || (base.UDPMode != "none" && base.UDPRepeats == 0) {
		return base, fmt.Errorf("repeats and udp_repeats must be 1..16")
	}
	if (presence["ttl"] != nil && base.TTL == 0) || (presence["udp_ttl"] != nil && base.UDPTTL == 0) || base.TTL < 0 || base.TTL > 255 || base.UDPTTL < 0 || base.UDPTTL > 255 || (fake && base.TTL == 0) || (base.UDPMode != "none" && base.UDPTTL == 0) {
		return base, fmt.Errorf("ttl and udp_ttl must be 1..255")
	}
	if base.Delay < 0 || time.Duration(base.Delay) > time.Second {
		return base, fmt.Errorf("delay must be 0..1s")
	}
	if base.QUICRepeats < 0 || base.QUICRepeats > 16 {
		return base, fmt.Errorf("quic_repeats must be 0..16 (0 inherits udp_repeats)")
	}
	if base.UDPMode == "quic" || base.UDPMode == "auto" {
		if base.QUICDesync == nil {
			enabled := true
			base.QUICDesync = &enabled
		}
		if !*base.QUICDesync && base.QUICRepeats > 0 {
			return base, fmt.Errorf("quic_repeats requires quic_desync=true")
		}
		if !*base.QUICDesync && base.UDPMode == "quic" && base.UDPLen > 0 {
			return base, fmt.Errorf("udplen requires quic_desync=true for udp_mode=quic")
		}
	} else if base.QUICDesync != nil || base.QUICRepeats != 0 {
		return base, fmt.Errorf("QUIC options require udp_mode=quic or auto")
	}
	if !desyncContains([]string{"none", "quic", "stun", "auto"}, base.UDPMode) {
		return base, fmt.Errorf("unknown udp_mode %q", base.UDPMode)
	}
	for key, value := range map[string]string{"fake_payload": base.FakePayload, "udp_fake_payload": base.UDPFakePayload, "syndata": base.SynData} {
		if value != "" {
			b, err := base64.StdEncoding.Strict().DecodeString(value)
			if err != nil || len(b) == 0 || len(b) > 65507 {
				return base, fmt.Errorf("%s: expected base64 payload of 1..65507 bytes", key)
			}
		}
	}
	if len(base.FakeSNIPool) > 64 {
		return base, fmt.Errorf("fake_sni_pool: at most 64 names")
	}
	names := append([]string{base.FakeSNI, base.FakeHost}, base.FakeSNIPool...)
	for _, s := range names {
		if len(s) > 253 || strings.ContainsAny(s, "\r\n\x00 \t") {
			return base, fmt.Errorf("invalid fake hostname %q", s)
		}
	}
	if _, _, err := ParseDesyncUDPRange(base.UDPOutRange); base.UDPOutRange != "" && err != nil {
		return base, err
	}
	if base.SeqOvl < 0 || base.SeqOvl > 65535 || base.IPFrag < 0 || base.IPFrag > 65535 || base.WSize < 0 || base.WSize > 65535 || base.WScale < 0 || base.WScale > 14 || base.UDPLen < 0 || base.UDPLen > 65507 {
		return base, fmt.Errorf("desync numeric parameter outside bounds")
	}
	if !desyncContains(DesyncFoolingMethods, base.Fooling) {
		return base, fmt.Errorf("unknown fooling %q", base.Fooling)
	}
	if base.Detour != "" {
		return base, fmt.Errorf("desync detour is unsupported: requires an owned direct socket")
	}
	if base.TCPFastOpen || base.TCPMultiPath {
		return base, fmt.Errorf("desync requires TCP fast open and multipath disabled")
	}
	if base.AutoTune != nil && !*base.AutoTune && base.Adaptive != nil {
		return base, fmt.Errorf("adaptive conflicts with auto_tune=false")
	}
	if base.Adaptive != nil && (base.AutoTune == nil || !*base.AutoTune) {
		return base, fmt.Errorf("adaptive requires auto_tune=true or preset=auto")
	}
	if base.AutoTune != nil && *base.AutoTune {
		if base.Adaptive == nil {
			base.Adaptive = &DesyncAdaptiveOptions{}
		}
		a := *base.Adaptive
		for key, value := range map[string]bool{"max_attempts": a.MaxAttempts == 0, "max_concurrent": a.MaxConcurrent == 0, "max_entries": a.MaxEntries == 0, "ttl": a.TTL == 0, "timeout": a.Timeout == 0, "max_buffer": a.MaxBuffer == 0} {
			if _, explicit := a.present[key]; explicit && value {
				return base, fmt.Errorf("adaptive %s must be positive", key)
			}
		}
		if a.MaxAttempts == 0 {
			a.MaxAttempts = 3
		}
		if a.MaxConcurrent == 0 {
			a.MaxConcurrent = 2
		}
		if a.MaxEntries == 0 {
			a.MaxEntries = 1024
		}
		if a.TTL == 0 {
			a.TTL = badoption.Duration(24 * time.Hour)
		}
		if a.Timeout == 0 {
			a.Timeout = badoption.Duration(10 * time.Second)
		}
		if a.MaxBuffer == 0 {
			a.MaxBuffer = 32768
		}
		if a.MaxAttempts < 1 || a.MaxAttempts > 8 || a.MaxConcurrent < 1 || a.MaxConcurrent > 16 || a.MaxEntries < 16 || a.MaxEntries > 16384 || time.Duration(a.TTL) < time.Minute || time.Duration(a.TTL) > 7*24*time.Hour || time.Duration(a.Timeout) < time.Second || time.Duration(a.Timeout) > time.Minute || a.MaxBuffer < 512 || a.MaxBuffer > 65536 || len(a.NetworkID) > 256 {
			return base, fmt.Errorf("adaptive limits out of bounds")
		}
		base.Adaptive = &a
	}
	if err := ValidateDesyncExtensions(base); err != nil {
		return base, err
	}
	return base, nil
}

func ParseDesyncUDPRange(s string) (int, int, error) {
	p := strings.Split(s, ":")
	if len(p) != 2 {
		return 0, 0, fmt.Errorf("udp_out_range must be start:end (inclusive, 1-based)")
	}
	a, e1 := strconv.Atoi(p[0])
	b, e2 := strconv.Atoi(p[1])
	if e1 != nil || e2 != nil || a < 1 || b < a || b > 1024 {
		return 0, 0, fmt.Errorf("udp_out_range requires 1 <= start <= end <= 1024")
	}
	return a, b, nil
}

// ParseDesyncStrategy uses whitespace-separated key=value tokens; values containing
// whitespace must be JSON strings. Duplicate and unknown keys are rejected.
func ParseDesyncStrategy(s string) (DesyncOptions, error) {
	values := map[string]json.RawMessage{}
	s = strings.TrimSpace(s)
	if len(s) > 131072 {
		return DesyncOptions{}, fmt.Errorf("strategy exceeds 128 KiB")
	}
	for s != "" {
		eq := strings.IndexByte(s, '=')
		if eq <= 0 || strings.ContainsAny(s[:eq], " \t\r\n") {
			return DesyncOptions{}, fmt.Errorf("expected key=value")
		}
		key := s[:eq]
		s = s[eq+1:]
		if _, ok := values[key]; ok {
			return DesyncOptions{}, fmt.Errorf("duplicate strategy key %q", key)
		}
		if !desyncContains([]string{"preset", "mode", "split_pos", "tlsrec_pos", "segment_order", "fake_placement", "fake_delay", "fake_tls_random", "fake_tls_size", "fake_tls_template", "http_mod", "hostfake_mode", "quic_split_pos", "quic_order", "fake_sni", "fake_host", "fake_payload", "fake_sni_pool", "repeats", "delay", "ttl", "fooling", "tlsrec_first", "seqovl", "autottl", "ipfrag", "syndata", "wsize", "wscale", "udp_mode", "udp_fake_payload", "udp_ttl", "udp_repeats", "udp_out_range", "udp_keep_socket", "udplen", "quic_desync", "quic_repeats", "auto_tune", "adaptive"}, key) {
			return DesyncOptions{}, fmt.Errorf("%s is not a strategy token", key)
		}
		if key == "adaptive" || (key == "fake_sni_pool" && strings.HasPrefix(s, "[")) {
			dec := json.NewDecoder(strings.NewReader(s))
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				return DesyncOptions{}, fmt.Errorf("%s: %w", key, err)
			}
			s = s[dec.InputOffset():]
			if s != "" && !strings.ContainsAny(s[:1], " \r\n\t") {
				return DesyncOptions{}, fmt.Errorf("expected whitespace after %s JSON", key)
			}
			values[key] = raw
			s = strings.TrimSpace(s)
			continue
		}
		var token string
		if strings.HasPrefix(s, "\"") {
			dec := json.NewDecoder(strings.NewReader(s))
			if err := dec.Decode(&token); err != nil {
				return DesyncOptions{}, err
			}
			s = s[dec.InputOffset():]
			if s != "" && !strings.ContainsAny(s[:1], " \r\n\t") {
				return DesyncOptions{}, fmt.Errorf("expected space after quoted value")
			}
		} else {
			end := strings.IndexAny(s, " \t\r\n")
			if end < 0 {
				end = len(s)
			}
			token = s[:end]
			s = s[end:]
		}
		switch key {
		case "repeats", "ttl", "seqovl", "ipfrag", "wsize", "wscale", "udp_ttl", "udp_repeats", "udplen", "quic_repeats", "fake_tls_size":
			if _, err := strconv.Atoi(token); err != nil {
				return DesyncOptions{}, fmt.Errorf("%s must be an integer", key)
			}
			values[key] = json.RawMessage(token)
		case "tlsrec_first", "autottl", "udp_keep_socket", "auto_tune", "quic_desync", "fake_tls_random":
			if token != "true" && token != "false" {
				return DesyncOptions{}, fmt.Errorf("%s must be true or false", key)
			}
			values[key] = json.RawMessage(token)
		case "fake_sni_pool":
			b, _ := json.Marshal(strings.Split(token, ","))
			values[key] = b
		default:
			b, _ := json.Marshal(token)
			values[key] = b
		}
		s = strings.TrimSpace(s)
	}
	b, _ := json.Marshal(values)
	var result DesyncOptions
	err := json.Unmarshal(b, &result)
	return result, err
}

func ExportDesyncStrategy(o DesyncOptions) (string, error) {
	// Dialer settings are deliberately excluded: this format describes a strategy.
	o.DialerOptions = DialerOptions{}
	o.Strategy = ""
	presence := make(map[string]json.RawMessage)
	for key, value := range o.present {
		if key != "strategy" {
			presence[key] = value
		}
	}
	o.present = presence
	b, err := json.Marshal(o)
	if err != nil {
		return "", err
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	tokens := make([]string, 0, len(keys))
	for _, k := range keys {
		v := string(m[k])
		var s string
		if json.Unmarshal(m[k], &s) == nil {
			v = s
			if v == "" || strings.ContainsAny(v, " \r\n\t\"") {
				v = strconv.Quote(v)
			}
		}
		tokens = append(tokens, k+"="+v)
	}
	return strings.Join(tokens, " "), nil
}
