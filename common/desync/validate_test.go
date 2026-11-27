package desync

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestValidateDefaultsAndNoEffectOptions(t *testing.T) {
	for _, tc := range []struct{ name, input, want string }{{"default", `{}`, ""}, {"udp", `{"mode":"none","udp_mode":"stun"}`, ""}, {"rotation", `{"mode":"none","udp_mode":"quic","udp_keep_socket":false}`, ""}, {"inactive repeats", `{"mode":"split","repeats":2}`, "repeats>1"}, {"inactive delay", `{"mode":"none","delay":"1ms"}`, "delay requires"}, {"bad fragment", `{"mode":"split","ipfrag":7}`, "ipfrag"}, {"bad marker", `{"mode":"split","split_pos":"unknown"}`, "split_pos"}} {
		t.Run(tc.name, func(t *testing.T) {
			var o option.DesyncOptions
			if err := json.Unmarshal([]byte(tc.input), &o); err != nil {
				t.Fatal(err)
			}
			normalized, err := option.NormalizeDesyncOptions(o)
			if err == nil {
				err = Validate(normalized)
			}
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v want %q", err, tc.want)
			}
		})
	}
}
