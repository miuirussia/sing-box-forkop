package desync

import (
	"reflect"
	"runtime"
	"strings"

	"github.com/sagernet/sing-box/option"
)

// Capabilities describes compiled support and runtime prerequisites separately;
// Validate/socket operations still check the actual kernel and privileges.
func Capabilities() map[string]any {
	parameters := map[string]any{}
	linuxOnly := map[string]bool{"fake_sni": true, "fake_host": true, "fake_payload": true, "fake_sni_pool": true, "ttl": true, "fooling": true, "seqovl": true, "autottl": true, "ipfrag": true, "syndata": true, "wsize": true, "wscale": true}
	t := reflect.TypeFor[option.DesyncOptions]()
	for i := 1; i < t.NumField(); i++ {
		key := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
		if key == "" || key == "-" {
			continue
		}
		supported := !linuxOnly[key] || runtime.GOOS == "linux"
		reason := ""
		if linuxOnly[key] {
			reason = "Linux; raw/SYN features require CAP_NET_RAW and/or CAP_NET_ADMIN"
		}
		parameters[key] = map[string]any{"supported": supported, "requirements": reason}
	}
	parameters["udp_keep_socket"] = map[string]any{"supported": true, "requirements": "false uses ephemeral raw UDP injector, Linux CAP_NET_RAW; true retains original socket"}
	parameters["udplen"] = map[string]any{"supported": true, "requirements": "STUN PADDING and protected QUIC Initial v1/v2/draft29; non-Initial packets unchanged"}
	parameters["wscale"] = map[string]any{"supported": runtime.GOOS == "linux", "requirements": "pre-SYN TCP_WINDOW_CLAMP; positive scale conflicts with exact small wsize; restored receive buffer remains socket-locked"}
	modes := map[string]any{}
	for _, mode := range option.DesyncModes {
		raw := mode != "none" && mode != "split" && mode != "multi_split" && mode != "tlsrec"
		reason := ""
		if raw {
			reason = "Linux CAP_NET_RAW and CAP_NET_ADMIN"
		}
		modes[mode] = map[string]any{"supported": !raw || runtime.GOOS == "linux", "requirements": reason}
	}
	return map[string]any{"capability": Capability, "version": 1, "supported": true, "platform": runtime.GOOS, "modes": option.DesyncModes, "presets": option.DesyncPresets, "mode_support": modes, "parameters": parameters, "active_api": "/desync"}
}
