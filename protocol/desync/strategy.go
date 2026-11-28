package desync

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	engine "github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/option"
)

const maxAdaptiveStrategies = 32

// Bypass DesyncOptions.MarshalJSON: presence describes the user's constraints,
// not the effective strategy, and must not leak into identities or new trials.
type strategyOptions option.DesyncOptions

func strategyParams(o option.DesyncOptions) map[string]json.RawMessage {
	o.DialerOptions = option.DialerOptions{}
	o.Preset, o.Strategy = "", ""
	o.AutoTune, o.Adaptive = nil, nil
	data, _ := json.Marshal(strategyOptions(o))
	params := make(map[string]json.RawMessage)
	_ = json.Unmarshal(data, &params)
	if o.WScaleExplicit {
		params["wscale"], _ = json.Marshal(o.WScale)
	}
	return params
}

// strategyID is stable across routing, tuning and import/export metadata. Its
// input is the normalized effective configuration used for the connection.
func strategyID(o option.DesyncOptions) string {
	// Spellings of the same effective defaults must share learning, including
	// independently specified TLS record positions that inherit split_pos.
	if o.TLSRecPos == "" && (o.Mode == "tlsrec" || o.TLSRecFirst) {
		o.TLSRecPos = o.SplitPos
	}
	if o.FakePlacement == "before" {
		o.FakePlacement = ""
	}
	if o.FakeTLSTemplate == "original" {
		o.FakeTLSTemplate = ""
	}
	if o.HostFakeMode == "legacy" {
		o.HostFakeMode = ""
	}
	defaultOrder := "forward"
	if strings.Contains(o.Mode, "disorder") || o.Mode == "disoob" {
		defaultOrder = "reverse"
	}
	if o.SegmentOrder == defaultOrder {
		o.SegmentOrder = ""
	}
	if o.QUICOrder == "forward" {
		o.QUICOrder = ""
	}
	if o.HTTPMod != "" {
		mods := strings.Split(o.HTTPMod, ",")
		slices.Sort(mods)
		o.HTTPMod = strings.Join(mods, ",")
	}
	data, _ := json.Marshal(strategyParams(o))
	sum := sha256.Sum256(data)
	return o.Mode + ":" + hex.EncodeToString(sum[:16])
}

func cloneDesyncOptions(o option.DesyncOptions) option.DesyncOptions {
	// Reconstruct presence from current values, including explicit zero/false.
	// The engine uses these to distinguish disabled fake delay and UDP socket
	// retention from inherited defaults.
	data, _ := json.Marshal(o)
	var cloned option.DesyncOptions
	_ = json.Unmarshal(data, &cloned)
	result := cloned
	// These fields are intentionally absent from JSON, but still belong to the
	// dialer's effective socket configuration.
	result.SocketControl = o.SocketControl
	result.SocketControlOwnsBind = o.SocketControlOwnsBind
	result.TCPKeepAliveSystemDefaults = o.TCPKeepAliveSystemDefaults
	result.UDPBindPort = o.UDPBindPort
	result.UDPFragmentDefault = o.UDPFragmentDefault
	result.WScaleExplicit = o.WScaleExplicit
	return result
}

func adaptiveCatalog(o option.DesyncOptions) []option.DesyncOptions {
	effective := o
	effective.DialerOptions = option.DialerOptions{}
	data, _ := json.Marshal(effective)
	params := make(map[string]json.RawMessage)
	_ = json.Unmarshal(data, &params)
	for _, key := range []string{"preset", "strategy", "auto_tune", "adaptive"} {
		delete(params, key)
	}
	// Preserve effective zero settings when rebuilding fresh presence metadata.
	// In particular, false must not become UDP's default keep_socket=true.
	if o.UDPMode != "" && o.UDPMode != "none" {
		params["udp_keep_socket"], _ = json.Marshal(o.UDPKeepSocket)
	}
	if o.WScaleExplicit {
		params["wscale"], _ = json.Marshal(o.WScale)
	}
	defaults, _ := option.NormalizeDesyncOptions(option.DesyncOptions{Mode: o.Mode})
	defaultParams := strategyParams(defaults)
	constrained := func(key string) bool {
		return o.IsExplicit(key) || !bytes.Equal(params[key], defaultParams[key])
	}
	catalog := make([]option.DesyncOptions, 0, maxAdaptiveStrategies)
	seen := make(map[string]bool)
	add := func(mode string, changes map[string]any) {
		if len(catalog) == maxAdaptiveStrategies || (o.IsExplicit("mode") && mode != o.Mode) {
			return
		}
		trial := make(map[string]json.RawMessage, len(params))
		for key, value := range params {
			trial[key] = value
		}
		trial["mode"], _ = json.Marshal(mode)
		for key, value := range changes {
			encoded, _ := json.Marshal(value)
			if constrained(key) && !bytes.Equal(encoded, params[key]) {
				return
			}
			trial[key] = encoded
		}
		data, _ := json.Marshal(trial)
		var candidate option.DesyncOptions
		if json.Unmarshal(data, &candidate) != nil {
			return
		}
		candidate, err := option.NormalizeDesyncOptions(candidate)
		if err != nil {
			return
		}
		candidate.DialerOptions = cloneDesyncOptions(o).DialerOptions
		candidate.WScaleExplicit = o.WScaleExplicit
		if engine.Validate(candidate) != nil {
			return
		}
		id := strategyID(candidate)
		if !seen[id] {
			seen[id] = true
			catalog = append(catalog, candidate)
		}
	}
	add(o.Mode, nil)
	for _, mode := range []string{"split", "tlsrec", "multi_split", "disorder", "fake_split"} {
		if mode == "multi_split" && !constrained("split_pos") {
			add(mode, map[string]any{"split_pos": "1,midsld"})
			continue
		}
		add(mode, nil)
	}

	// Offer individual axes, not a Cartesian product: every family gets useful
	// trials before the catalogue reaches its hard persistence/probing bound.
	splitMode := o.Mode
	switch splitMode {
	case "none", "fake", "oob", "tlsrec":
		splitMode = "split"
	}
	recordMode := "tlsrec"
	if o.TLSRecFirst {
		recordMode = o.Mode
	}
	for _, pos := range []string{"6", "sni+1", "midsld"} {
		add(recordMode, map[string]any{"tlsrec_pos": pos})
	}
	for _, pos := range []string{"1", "sni+1", "1,midsld", "host+1,midsld,endhost-1"} {
		add(splitMode, map[string]any{"split_pos": pos})
	}
	delayMode := o.Mode
	if delayMode == "none" {
		delayMode = "split"
	}
	for _, delay := range []string{"5ms", "20ms"} {
		add(delayMode, map[string]any{"delay": delay})
	}
	add(splitMode, map[string]any{"tlsrec_first": true, "tlsrec_pos": "6"})
	add(splitMode, map[string]any{"tlsrec_first": true, "tlsrec_pos": "sni+1"})
	add(splitMode, map[string]any{"segment_order": "reverse"})

	fakeMode := o.Mode
	switch fakeMode {
	case "fake", "fake_split", "fake_disorder", "hostfakesplit", "oob", "disoob":
	default:
		fakeMode = "fake_split"
	}
	for _, placement := range []string{"between", "before_between"} {
		add(fakeMode, map[string]any{"fake_placement": placement})
	}
	add(fakeMode, map[string]any{"fake_delay": "5ms"})
	if o.FakePayload == "" {
		add(fakeMode, map[string]any{"fake_tls_random": true})
		add(fakeMode, map[string]any{"fake_tls_size": 4096})
		add(fakeMode, map[string]any{"fake_tls_size": 8192})
		add(fakeMode, map[string]any{"fake_tls_template": "compact"})
	}
	add("hostfakesplit", map[string]any{"hostfake_mode": "replace"})
	for _, mod := range []string{"hcsmix", "dcsmix", "rmspace", "hcsmix,dcsmix,rmspace"} {
		add(splitMode, map[string]any{"http_mod": mod})
	}
	// This catalogue is learned by TCP connections. UDP options remain fixed;
	// varying QUIC here would spend TCP retry slots on identical TCP traffic.
	if len(catalog) == 0 {
		catalog = append(catalog, cloneDesyncOptions(o))
	}
	return catalog
}
