package option

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestDesyncExtendedStrategyRoundTrip(t *testing.T) {
	input := `mode=fake_split split_pos=sni+1,endhost-1 tlsrec_first=true tlsrec_pos=midsld segment_order=2,1,3 fake_placement=before_between fake_delay=0s fake_tls_random=true fake_tls_size=1024 fake_tls_template=compact http_mod=hcsmix,dcsmix,rmspace udp_mode=quic quic_split_pos=sni+1 quic_order=reverse`
	o, err := ParseDesyncStrategy(input)
	if err != nil {
		t.Fatal(err)
	}
	o, err = NormalizeDesyncOptions(o)
	if err != nil {
		t.Fatal(err)
	}
	exported, err := ExportDesyncStrategy(o)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseDesyncStrategy(exported)
	if err != nil {
		t.Fatal(err)
	}
	got, err = NormalizeDesyncOptions(got)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(o)
	b, _ := json.Marshal(got)
	var before, after map[string]any
	_ = json.Unmarshal(a, &before)
	_ = json.Unmarshal(b, &after)
	if !reflect.DeepEqual(before, after) || !got.IsExplicit("fake_delay") || !got.FakeTLSRandom {
		t.Fatalf("strategy changed across export/import:\n%s\n%s", a, b)
	}
}

func TestDesyncExtendedInvalidOptions(t *testing.T) {
	for _, tc := range []struct{ name, strategy string }{
		{"records disabled", "tlsrec_pos=midsld"},
		{"bad records marker", "mode=tlsrec tlsrec_pos=unknown"},
		{"record header", "mode=tlsrec tlsrec_pos=1"},
		{"record payload boundary", "mode=tlsrec tlsrec_pos=5"},
		{"inherited record header", "mode=tlsrec split_pos=1"},
		{"inherited first record header", "tlsrec_first=true split_pos=1"},
		{"duplicate segment", "segment_order=1,1"},
		{"missing segment", "segment_order=1,3"},
		{"order without segmentation", "mode=fake segment_order=reverse"},
		{"fake without mode", "fake_tls_random=true"},
		{"fake delay bound", "mode=fake fake_delay=2s"},
		{"fake size bound", "mode=fake fake_tls_size=60001"},
		{"fake template", "mode=fake fake_tls_template=chrome"},
		{"fake placement", "mode=fake_split fake_placement=after"},
		{"placement without segmentation", "mode=fake fake_placement=between"},
		{"duplicate HTTP transform", "http_mod=hcsmix,hcsmix"},
		{"unknown HTTP transform", "http_mod=unixeol"},
		{"host replacement mode", "hostfake_mode=replace"},
		{"host replacement custom payload", "mode=hostfakesplit hostfake_mode=replace fake_payload=YWJj"},
		{"host replacement size", "mode=hostfakesplit hostfake_mode=replace fake_tls_size=512"},
		{"QUIC disabled", "quic_split_pos=midsld"},
		{"QUIC explicitly disabled", "udp_mode=quic quic_desync=false quic_split_pos=1"},
		{"QUIC missing split", "udp_mode=quic quic_order=reverse"},
		{"QUIC duplicate order", "udp_mode=quic quic_split_pos=1 quic_order=2,2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, err := ParseDesyncStrategy(tc.strategy)
			if err == nil {
				_, err = NormalizeDesyncOptions(o)
			}
			if err == nil {
				t.Fatal("invalid strategy accepted")
			}
		})
	}
}

func TestDesyncProgrammaticWindowScaleZeroRoundTrip(t *testing.T) {
	o, err := NormalizeDesyncOptions(DesyncOptions{Mode: "split", WScaleExplicit: true})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	var got DesyncOptions
	if err = json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	got, err = NormalizeDesyncOptions(got)
	if err != nil || !got.WScaleExplicit || got.WScale != 0 {
		t.Fatalf("explicit zero window scale lost across JSON: %s, %v", data, err)
	}
}
