package option

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestDesyncOverridesAndRoundTrip(t *testing.T) {
	for _, data := range []string{
		`{"preset":"GT4","udp_keep_socket":false,"udp_repeats":2}`,
		`{"preset":"auto","auto_tune":false,"mode":"none"}`,
		`{"preset":"fake","strategy":"mode=split delay=1ms","mode":"tlsrec","delay":"0s"}`,
	} {
		t.Run(data, func(t *testing.T) {
			var raw DesyncOptions
			if err := json.Unmarshal([]byte(data), &raw); err != nil {
				t.Fatal(err)
			}
			o, err := NormalizeDesyncOptions(raw)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(o)
			if err != nil {
				t.Fatal(err)
			}
			var next DesyncOptions
			if err = json.Unmarshal(encoded, &next); err != nil {
				t.Fatal(err)
			}
			next, err = NormalizeDesyncOptions(next)
			if err != nil {
				t.Fatal(err)
			}
			again, _ := json.Marshal(next)
			if string(encoded) != string(again) {
				t.Fatalf("not stable: %s -> %s", encoded, again)
			}
			if strings.Contains(data, `"udp_keep_socket":false`) && o.UDPKeepSocket {
				t.Fatal("explicit false overridden")
			}
			if strings.Contains(data, `"auto_tune":false`) && (o.AutoTune == nil || *o.AutoTune) {
				t.Fatal("manual strategy enabled adaptive")
			}
			if strings.Contains(data, `"delay":"0s"`) && (o.Delay != 0 || o.Mode != "tlsrec") {
				t.Fatal("explicit options did not override imported/preset")
			}
		})
	}
}
func TestDesyncInvalid(t *testing.T) {
	for _, input := range []string{`mdoe=split`, `mode=split mode=fake`, `ttl=0`, `udp_mode=wat`, `udp_out_range=0:4`, `split_pos=sni+++1`, `repeats=100`, `delay=-1s`, `auto_tune=on`, `fake_payload=!!!`, `mode="split"garbage`, `adaptive=x`, `strategy=x`, `detour=proxy`, `{"mode":"split","unknown":true}`, `{"auto_tune":false,"adaptive":{}}`, `{"auto_tune":true,"adaptive":{"max_attempts":99}}`, `{"preset":"GT1","udp_keep_socket":false,"udp_repeats":0}`} {
		t.Run(input, func(t *testing.T) {
			var o DesyncOptions
			var err error
			if strings.HasPrefix(input, "{") {
				err = json.Unmarshal([]byte(input), &o)
			} else {
				o, err = ParseDesyncStrategy(input)
			}
			if err == nil {
				_, err = NormalizeDesyncOptions(o)
			}
			if err == nil {
				t.Fatalf("accepted invalid %s", input)
			}
		})
	}
}
func TestDesyncStrategyExport(t *testing.T) {
	raw, err := ParseDesyncStrategy(`mode=multi_split split_pos=sniext+1,midsld-1,endhost-1 delay=0s auto_tune=false fake_sni_pool=a.example,b.example`)
	if err != nil {
		t.Fatal(err)
	}
	text, err := ExportDesyncStrategy(raw)
	if err != nil {
		t.Fatal(err)
	}
	next, err := ParseDesyncStrategy(text)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(raw.FakeSNIPool, next.FakeSNIPool) || raw.SplitPos != next.SplitPos || next.AutoTune == nil || *next.AutoTune {
		t.Fatalf("roundtrip: %s %+v", text, next)
	}
}
func FuzzDesyncStrategy(f *testing.F) {
	for _, s := range []string{"mode=split split_pos=midsld", "auto_tune=false", "mode=\"split\"", "=", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		o, err := ParseDesyncStrategy(s)
		if err != nil {
			return
		}
		_, _ = NormalizeDesyncOptions(o)
		encoded, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		var again DesyncOptions
		if err = json.Unmarshal(encoded, &again); err != nil {
			t.Fatal(err)
		}
	})
}

func TestDesyncImportedPreset(t *testing.T) {
	for _, tc := range []struct{ input, mode, udp string }{{`{"strategy":"preset=GT2"}`, "none", "auto"}, {`{"strategy":"preset=fake mode=split"}`, "split", "none"}, {`{"preset":"custom","strategy":"preset=GT2"}`, "split", "none"}} {
		var raw DesyncOptions
		if err := json.Unmarshal([]byte(tc.input), &raw); err != nil {
			t.Fatal(err)
		}
		o, err := NormalizeDesyncOptions(raw)
		if err != nil {
			t.Fatal(err)
		}
		if o.Mode != tc.mode || o.UDPMode != tc.udp {
			t.Fatalf("%s -> %+v", tc.input, o)
		}
	}
}

func TestDesyncRejectsNullAndZeroLimits(t *testing.T) {
	for _, input := range []string{`null`, `{"mode":null}`, `{"auto_tune":true,"adaptive":{"max_attempts":0}}`, `{"auto_tune":true,"adaptive":{"ttl":"0s"}}`, `{"auto_tune":true,"adaptive":{"timeout":null}}`} {
		var raw DesyncOptions
		err := json.Unmarshal([]byte(input), &raw)
		if err == nil {
			_, err = NormalizeDesyncOptions(raw)
		}
		if err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}

func TestDesyncStructuredStrategyRoundtrip(t *testing.T) {
	input := `preset=auto adaptive={"max_attempts": 2, "network_id": "home network"} fake_sni_pool=["a.example", "b.example"]`
	o, err := ParseDesyncStrategy(input)
	if err != nil {
		t.Fatal(err)
	}
	if o.Adaptive == nil || o.Adaptive.NetworkID != "home network" || len(o.FakeSNIPool) != 2 {
		t.Fatalf("bad structured import: %+v", o)
	}
	encoded, err := ExportDesyncStrategy(o)
	if err != nil {
		t.Fatal(err)
	}
	next, err := ParseDesyncStrategy(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if next.Adaptive == nil || next.Adaptive.MaxAttempts != 2 || !reflect.DeepEqual(next.FakeSNIPool, o.FakeSNIPool) {
		t.Fatalf("bad roundtrip %s", encoded)
	}
}

func TestDesyncExplicitEmptyClearsDefault(t *testing.T) {
	var raw DesyncOptions
	if err := json.Unmarshal([]byte(`{"preset":"fake","fooling":""}`), &raw); err != nil {
		t.Fatal(err)
	}
	o, err := NormalizeDesyncOptions(raw)
	if err != nil {
		t.Fatal(err)
	}
	if o.Fooling != "" {
		t.Fatal("explicit empty fooling replaced by default")
	}
	exported, err := ExportDesyncStrategy(o)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(exported, `fooling=""`) {
		t.Fatalf("empty strings need quotes for portable import: %s", exported)
	}
	raw, err = ParseDesyncStrategy("mode=none split_pos=1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NormalizeDesyncOptions(raw); err == nil {
		t.Fatal("accepted no-effect split_pos in none mode")
	}
}

func TestDesyncQUICOverrides(t *testing.T) {
	for _, input := range []string{`{"preset":"GT4","quic_desync":false}`, `{"udp_mode":"quic","quic_repeats":3}`, `{"udp_mode":"auto","quic_repeats":0}`} {
		var raw DesyncOptions
		if err := json.Unmarshal([]byte(input), &raw); err != nil {
			t.Fatal(err)
		}
		o, err := NormalizeDesyncOptions(raw)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := ExportDesyncStrategy(o)
		if err != nil {
			t.Fatal(err)
		}
		next, err := ParseDesyncStrategy(encoded)
		if err != nil {
			t.Fatal(err)
		}
		next, err = NormalizeDesyncOptions(next)
		if err != nil {
			t.Fatal(err)
		}
		if next.QUICDesync == nil || *next.QUICDesync != *o.QUICDesync || next.QUICRepeats != o.QUICRepeats {
			t.Fatalf("lost quic override: %s", encoded)
		}
	}
	for _, input := range []string{"quic_desync=true", "udp_mode=quic quic_desync=false quic_repeats=1", "udp_mode=quic quic_repeats=17"} {
		raw, err := ParseDesyncStrategy(input)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = NormalizeDesyncOptions(raw); err == nil {
			t.Fatalf("accepted invalid quic options %s", input)
		}
	}
}

func TestDesyncTLSRecFirstSplitPositions(t *testing.T) {
	for _, mode := range []string{"fake", "oob"} {
		for _, explicit := range []bool{false, true} {
			input := fmt.Sprintf(`{"mode":%q,"tlsrec_first":true`, mode)
			want := "midsld"
			if explicit {
				input += `,"split_pos":"sni+1"`
				want = "sni+1"
			}
			input += "}"
			var raw DesyncOptions
			if err := json.Unmarshal([]byte(input), &raw); err != nil {
				t.Fatal(err)
			}
			o, err := NormalizeDesyncOptions(raw)
			if err != nil {
				t.Fatal(err)
			}
			if o.SplitPos != want {
				t.Fatalf("%s -> %q, want %q", input, o.SplitPos, want)
			}
			encoded, err := ExportDesyncStrategy(o)
			if err != nil {
				t.Fatal(err)
			}
			next, err := ParseDesyncStrategy(encoded)
			if err != nil {
				t.Fatal(err)
			}
			next, err = NormalizeDesyncOptions(next)
			if err != nil || next.SplitPos != want || !next.TLSRecFirst {
				t.Fatalf("roundtrip %s: %+v %v", encoded, next, err)
			}
		}
	}
}
