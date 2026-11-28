package desync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	engine "github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func strategyForTest(t *testing.T, raw string) option.DesyncOptions {
	t.Helper()
	var o option.DesyncOptions
	if err := json.Unmarshal([]byte(raw), &o); err != nil {
		t.Fatal(err)
	}
	o, err := option.NormalizeDesyncOptions(o)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestStrategyIDParameters(t *testing.T) {
	for _, tc := range []struct {
		name, first, second string
	}{
		{"split position", `{"split_pos":"1"}`, `{"split_pos":"sni+1"}`},
		{"explicit window scale zero", `{}`, `{"wscale":0}`},
		{"delay", `{"delay":"5ms"}`, `{"delay":"20ms"}`},
		{"TLS record position", `{"tlsrec_first":true,"tlsrec_pos":"6"}`, `{"tlsrec_first":true,"tlsrec_pos":"7"}`},
		{"segment order", `{"segment_order":"reverse"}`, `{"segment_order":"sni_last"}`},
		{"fake placement", `{"mode":"fake_split","fake_placement":"before"}`, `{"mode":"fake_split","fake_placement":"between"}`},
		{"fake delay", `{"mode":"fake_split"}`, `{"mode":"fake_split","fake_delay":"5ms"}`},
		{"disabled fake delay", `{"mode":"fake_split","delay":"5ms"}`, `{"mode":"fake_split","delay":"5ms","fake_delay":"0s"}`},
		{"fake random", `{"mode":"fake_split","fake_tls_random":false}`, `{"mode":"fake_split","fake_tls_random":true}`},
		{"fake size", `{"mode":"fake_split","fake_tls_size":512}`, `{"mode":"fake_split","fake_tls_size":1024}`},
		{"fake template", `{"mode":"fake_split","fake_tls_template":"original"}`, `{"mode":"fake_split","fake_tls_template":"compact"}`},
		{"fake pool", `{"mode":"fake_split","fake_sni_pool":["one.example"]}`, `{"mode":"fake_split","fake_sni_pool":["two.example"]}`},
		{"HTTP", `{"http_mod":"hcsmix"}`, `{"http_mod":"dcsmix"}`},
		{"host fake", `{"mode":"hostfakesplit","hostfake_mode":"legacy"}`, `{"mode":"hostfakesplit","hostfake_mode":"replace"}`},
		{"QUIC position", `{"udp_mode":"quic","quic_split_pos":"1"}`, `{"udp_mode":"quic","quic_split_pos":"midsld"}`},
		{"QUIC order", `{"udp_mode":"quic","quic_split_pos":"1","quic_order":"forward"}`, `{"udp_mode":"quic","quic_split_pos":"1","quic_order":"reverse"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first, second := strategyForTest(t, tc.first), strategyForTest(t, tc.second)
			id := strategyID(first)
			if id == strategyID(second) {
				t.Fatalf("different configurations share %s", id)
			}
			if !strings.HasPrefix(id, first.Mode+":") || len(id) != len(first.Mode)+33 {
				t.Fatalf("missing readable mode or stable hash: %s", id)
			}
		})
	}
}

func TestStrategyIDEquivalentConfigurations(t *testing.T) {
	for _, tc := range []struct {
		name, first, second string
	}{
		{"metadata and presence", `{"preset":"auto"}`, `{"preset":"custom","mode":"split","split_pos":"midsld","delay":"0s","tlsrec_first":false,"auto_tune":false,"bind_interface":"other"}`},
		{"strategy import", `{"preset":"auto","strategy":"split_pos=1 delay=5ms"}`, `{"mode":"split","split_pos":"1","delay":"5000us"}`},
		{"record inheritance", `{"mode":"tlsrec","split_pos":"6"}`, `{"mode":"tlsrec","split_pos":"6","tlsrec_pos":"6"}`},
		{"segment default", `{}`, `{"segment_order":"forward"}`},
		{"disorder default", `{"mode":"disorder"}`, `{"mode":"disorder","segment_order":"reverse"}`},
		{"fake defaults", `{"mode":"fake_split"}`, `{"mode":"fake_split","fake_placement":"before","fake_delay":"0s","fake_tls_random":false,"fake_tls_size":0,"fake_tls_template":"original"}`},
		{"inherited fake delay", `{"mode":"fake_split","delay":"5ms"}`, `{"mode":"fake_split","delay":"5ms","fake_delay":"5ms"}`},
		{"host fake default", `{"mode":"hostfakesplit"}`, `{"mode":"hostfakesplit","hostfake_mode":"legacy"}`},
		{"HTTP token order", `{"http_mod":"hcsmix,dcsmix,rmspace"}`, `{"http_mod":"rmspace,dcsmix,hcsmix"}`},
		{"QUIC default", `{"udp_mode":"quic","quic_split_pos":"1"}`, `{"udp_mode":"quic","quic_split_pos":"1","quic_order":"forward"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first, second := strategyForTest(t, tc.first), strategyForTest(t, tc.second)
			if strategyID(first) != strategyID(second) {
				t.Fatalf("equivalent configurations differ: %s / %s", strategyID(first), strategyID(second))
			}
		})
	}
	o := strategyForTest(t, `{"preset":"auto"}`)
	other := cloneDesyncOptions(o)
	other.Preset, other.Strategy = "GT4", "mode=none"
	other.Adaptive.NetworkID = "other network"
	other.Adaptive.MaxAttempts++
	if strategyID(o) != strategyID(other) {
		t.Fatal("metadata affected the effective identity")
	}
}

func TestAdaptiveCatalogBoundsAndCoverage(t *testing.T) {
	o := strategyForTest(t, `{"preset":"auto","udp_mode":"quic"}`)
	catalog := adaptiveCatalog(o)
	if len(catalog) < 8 || len(catalog) > maxAdaptiveStrategies {
		t.Fatalf("unexpected catalogue size %d", len(catalog))
	}
	if strategyID(catalog[0]) != strategyID(o) {
		t.Fatal("original strategy was not first")
	}
	seen := make(map[string]bool)
	coverage := make(map[string]map[string]bool)
	repeated := adaptiveCatalog(o)
	for i, candidate := range catalog {
		if err := engine.Validate(candidate); err != nil {
			t.Fatalf("invalid candidate %+v: %v", candidate, err)
		}
		id := strategyID(candidate)
		if seen[id] || id != strategyID(repeated[i]) {
			t.Fatalf("duplicate or unstable candidate %s", id)
		}
		seen[id] = true
		if candidate.Preset != "" || candidate.Strategy != "" || candidate.Adaptive != nil || candidate.AutoTune != nil {
			t.Fatal("candidate retained tuning/import metadata")
		}
		for key, value := range strategyParams(candidate) {
			if coverage[key] == nil {
				coverage[key] = make(map[string]bool)
			}
			coverage[key][string(value)] = true
		}
	}
	fields := []string{"split_pos", "tlsrec_pos", "delay", "http_mod"}
	if runtime.GOOS == "linux" {
		fields = append(fields, "segment_order", "fake_placement", "fake_delay", "fake_tls_random", "fake_tls_size", "fake_tls_template", "hostfake_mode")
	}
	for _, field := range fields {
		if len(coverage[field]) == 0 {
			t.Errorf("no catalogue variant for %s", field)
		}
	}
	if len(coverage["split_pos"]) < 3 || len(coverage["tlsrec_pos"]) < 2 || len(coverage["delay"]) < 2 {
		t.Fatalf("insufficient position/delay diversity: %+v", coverage)
	}
	for _, candidate := range catalog {
		if candidate.QUICSplitPos != o.QUICSplitPos || candidate.QUICOrder != o.QUICOrder {
			t.Fatal("TCP learning changed UDP-only parameters")
		}
	}
}

func TestAdaptiveCatalogExplicitConstraints(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		keys      []string
	}{
		{"split defaults", `{"preset":"auto","split_pos":"midsld","delay":"0s","tlsrec_first":false,"http_mod":""}`, []string{"split_pos", "delay", "tlsrec_first", "http_mod"}},
		{"record", `{"preset":"auto","mode":"tlsrec","split_pos":"midsld","tlsrec_pos":"sni+1","delay":"5ms"}`, []string{"mode", "split_pos", "tlsrec_pos", "delay"}},
		{"imported", `{"preset":"auto","strategy":"mode=tlsrec tlsrec_pos=sni+1 delay=0s"}`, []string{"mode", "tlsrec_pos", "delay"}},
		{"order", `{"preset":"auto","segment_order":"reverse"}`, []string{"segment_order"}},
		{"fake defaults", `{"preset":"auto","mode":"fake_split","fake_placement":"before","fake_delay":"0s","fake_tls_random":false,"fake_tls_size":0,"fake_tls_template":"original"}`, []string{"mode", "fake_placement", "fake_delay", "fake_tls_random", "fake_tls_size", "fake_tls_template"}},
		{"host fake", `{"preset":"auto","mode":"hostfakesplit","hostfake_mode":"legacy"}`, []string{"mode", "hostfake_mode"}},
		{"QUIC", `{"preset":"auto","udp_mode":"quic","quic_split_pos":"midsld","quic_order":"forward","udp_keep_socket":false}`, []string{"udp_mode", "quic_split_pos", "quic_order", "udp_keep_socket"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := strategyForTest(t, tc.raw)
			if engine.Validate(o) != nil {
				t.Skip("strategy unavailable on this platform")
			}
			before, _ := json.Marshal(o)
			original := strategyParams(o)
			catalog := adaptiveCatalog(o)
			if len(catalog) == 0 || len(catalog) > maxAdaptiveStrategies || strategyID(catalog[0]) != strategyID(o) {
				t.Fatal("catalogue bounds or original strategy violated")
			}
			for _, candidate := range catalog {
				params := strategyParams(candidate)
				for _, key := range tc.keys {
					if !bytes.Equal(original[key], params[key]) {
						t.Errorf("explicit %s changed from %s to %s", key, original[key], params[key])
					}
				}
			}
			after, _ := json.Marshal(o)
			if !bytes.Equal(before, after) {
				t.Fatal("catalogue generation mutated user options/presence")
			}
		})
	}
}

func TestAdaptiveCatalogPreservesCustomFakeBytes(t *testing.T) {
	o := strategyForTest(t, `{"preset":"auto","mode":"fake_split","fake_payload":"Q1VTVE9NLUJMSU5BUlk="}`)
	for _, candidate := range adaptiveCatalog(o) {
		if candidate.FakePayload != o.FakePayload || candidate.FakeTLSRandom || candidate.FakeTLSSize != 0 || candidate.FakeTLSTemplate != "" {
			t.Fatal("automatic TLS transformations would reject the configured binary fake")
		}
	}
}

func TestAdaptiveCatalogDoesNotReapplyMetadata(t *testing.T) {
	o := strategyForTest(t, `{"preset":"auto","split_pos":"host+2","delay":"7ms"}`)
	o.Preset, o.Strategy = "GT4", "mode=fake split_pos=1 delay=99ms"
	catalog := adaptiveCatalog(o)
	if strategyID(catalog[0]) != strategyID(o) {
		t.Fatal("stale import or preset changed the original effective strategy")
	}
	for _, candidate := range catalog {
		if candidate.SplitPos != o.SplitPos || candidate.Delay != o.Delay || candidate.UDPMode != o.UDPMode {
			t.Fatal("stale import, preset or presence changed a candidate")
		}
	}
	// Programmatic callers have no JSON presence; non-default settings are
	// constraints too, even after normalization.
	o = option.DesyncOptions{Preset: "auto", SplitPos: "host+2", Delay: 7_000_000}
	o, err := option.NormalizeDesyncOptions(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range adaptiveCatalog(o) {
		if candidate.SplitPos != o.SplitPos || candidate.Delay != o.Delay {
			t.Fatal("programmatic constraint changed")
		}
	}
}

func TestAdaptiveOptionsDoNotAlias(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fake mode needs Linux")
	}
	o := strategyForTest(t, `{"preset":"auto","mode":"fake_split","fake_sni_pool":["one.example","two.example"],"udp_mode":"quic","domain_resolver":{"server":"dns"},"network_type":["wifi"]}`)
	a := NewAdaptive("alias", o)
	defer a.Close()
	before := cloneDesyncOptions(a.catalog[0])
	o.FakeSNIPool[0] = "changed.example"
	*o.QUICDesync = false
	*o.AutoTune = false
	o.Adaptive.MaxAttempts = 8
	o.DomainResolver.Server = "changed"
	beforeJSON, _ := json.Marshal(strategyOptions(before))
	afterJSON, _ := json.Marshal(strategyOptions(a.catalog[0]))
	if !bytes.Equal(beforeJSON, afterJSON) {
		t.Fatal("catalogue aliases source options")
	}
	if a.options.Adaptive.MaxAttempts == 8 || !*a.options.AutoTune || !*a.options.QUICDesync {
		t.Fatal("adaptive options alias caller state")
	}
	ranked := a.ranked([]string{"host:test"})
	ranked[0].FakeSNIPool[0] = "ranked.example"
	*ranked[0].QUICDesync = false
	ranked[0].DomainResolver.Server = "ranked"
	fresh := a.ranked([]string{"host:test"})
	if fresh[0].FakeSNIPool[0] != "one.example" || !*fresh[0].QUICDesync || fresh[0].DomainResolver.Server != "dns" {
		t.Fatal("ranked options alias catalogue or another call")
	}
	if len(fresh) > 1 && fresh[1].FakeSNIPool[0] != "one.example" {
		t.Fatal("catalogue candidates alias one another")
	}
}

func TestAdaptiveSameModeLearningAndReload(t *testing.T) {
	a := adaptiveForTest(t)
	a.catalog = []option.DesyncOptions{
		strategyForTest(t, `{"mode":"split","split_pos":"1"}`),
		strategyForTest(t, `{"mode":"split","split_pos":"2","delay":"5ms"}`),
	}
	first, second := strategyID(a.catalog[0]), strategyID(a.catalog[1])
	keys := destinationKeys(M.ParseSocksaddr("example.com:443"), 0)
	dials := 0
	conn, err := a.DialContext(context.Background(), M.ParseSocksaddr("example.com:443"), 0,
		func(context.Context, context.Context, M.Socksaddr, option.DesyncOptions) (net.Conn, error) {
			dials++
			if dials == 1 {
				return nil, errors.New("connect failed")
			}
			return &scriptedConn{reader: bytes.NewReader([]byte("response"))}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Read(make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	snapshot := a.Stats()
	if snapshot.Current != second || !strings.Contains(snapshot.LastSwitch, first+" -> "+second) {
		t.Fatalf("diagnostics do not distinguish same-mode strategies: %+v", snapshot)
	}
	for _, key := range keys {
		scores := snapshot.Entries[key].Strategies
		if len(scores) != 2 || scores[first].Failure != 1 || scores[second].Success != 1 {
			t.Fatalf("observations shared a mode-only score: %+v", scores)
		}
	}
	if strategyID(a.ranked(keys)[0]) != second {
		t.Fatal("same-mode winner was not ranked first")
	}
	a.store = new(memoryStore)
	if err = a.Flush(); err != nil {
		t.Fatal(err)
	}
	b := adaptiveForTest(t)
	b.catalog = a.catalog
	b.store = a.store
	if err = b.Load(); err != nil {
		t.Fatal(err)
	}
	beforeJSON, _ := json.Marshal(snapshot.Entries)
	afterJSON, _ := json.Marshal(b.Stats().Entries)
	if strategyID(b.ranked(keys)[0]) != second || !bytes.Equal(beforeJSON, afterJSON) {
		t.Fatal("reload lost independent same-mode learning")
	}
}

func TestAdaptiveSameModeReplayObservations(t *testing.T) {
	a := adaptiveForTest(t)
	a.catalog = []option.DesyncOptions{
		strategyForTest(t, `{"mode":"split","split_pos":"1"}`),
		strategyForTest(t, `{"mode":"split","split_pos":"2"}`),
	}
	first, second := strategyID(a.catalog[0]), strategyID(a.catalog[1])
	dials := 0
	conn, err := a.DialContext(context.Background(), M.ParseSocksaddr("example.com:443"), 0,
		func(context.Context, context.Context, M.Socksaddr, option.DesyncOptions) (net.Conn, error) {
			dials++
			var response []byte
			if dials > 1 {
				response = []byte("server hello")
			}
			return &scriptedConn{reader: bytes.NewReader(response)}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Write(helloForTest()); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Read(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	snapshot := a.Stats()
	if dials != 2 || snapshot.Current != second {
		t.Fatal("same-mode replay did not switch to the second configuration")
	}
	for _, entry := range snapshot.Entries {
		if len(entry.Strategies) != 2 || entry.Strategies[first].Failure != 1 || entry.Strategies[second].Success != 1 {
			t.Fatalf("read/replay observations conflated configurations: %+v", entry.Strategies)
		}
	}
}

func TestAdaptiveLoadIgnoresLegacyModeScores(t *testing.T) {
	a := adaptiveForTest(t)
	keys := destinationKeys(M.ParseSocksaddr("example.com:443"), 0)
	id := strategyID(a.catalog[2])
	snapshot := Snapshot{
		Version: 1, Partition: a.partition, RouteGeneration: 3,
		Entries: map[string]*Entry{
			keys[0]: {Updated: time.Now(), Strategies: map[string]Score{
				"tlsrec": {Success: 1000}, id: {Success: 5},
			}},
			"legacy only": {Updated: time.Now(), Strategies: map[string]Score{"split": {Success: 1000}}},
		},
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	a.store = &memoryStore{data: data}
	if err = a.Load(); err != nil {
		t.Fatal(err)
	}
	loaded := a.Stats()
	if loaded.Version != 1 || loaded.RouteGeneration != 3 || len(loaded.Entries) != 1 || len(loaded.Entries[keys[0]].Strategies) != 1 {
		t.Fatalf("legacy snapshot was migrated or misattributed: %+v", loaded)
	}
	if strategyID(a.ranked(keys)[0]) != id {
		t.Fatal("legacy mode-only score overrode an exact configuration")
	}
}
